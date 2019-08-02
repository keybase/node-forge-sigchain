# Fragments copied from server.

{make_esc} = require 'iced-error'
{createHash,createHmac} = require 'crypto'
kbpgp = require 'kbpgp'
kb = kbpgp.kb
{KeyManager,EncKeyManager} = kbpgp.kb
{pack,unpack} = require 'purepack'
nacl = require 'keybase-nacl'

#=============================================================

exports.kdf = kdf = ({key,context,alg,enc}) ->
  alg or= "sha512"
  if typeof(key) is "string"
    throw new Error "kdf key is string, expected buffer"
  ret = createHmac(alg, key).update(context).digest()[0...32]
  if enc? then ret.toString(enc) else ret

##=======================================================================

exports.derive_key = derive_key = ({key, who, which, omit_prefix, alg, enc}) ->
  prefix = if omit_prefix then "" else "Keybase-"
  context = "#{prefix}Derived-#{who}-NaCl-#{which}-1"
  kdf { key, context, alg, enc }

##=======================================================================

class PerXSecretKeys

  constructor : ({@seed, @kms, @who, @secret_box_key, @prng}) ->
    @seed or= @prng(32)
    @kms or= {}
    @secret_box_key or= null

  get_kms : () -> @kms
  get_seed : () -> @seed
  get_secret_box_key : () -> @secret_box_key

  derive : (opts, cb) ->
    esc = make_esc cb, "derive"
    alg =         if @who is "User" then "sha256" else "sha512"
    omit_prefix = if @who is "User" then true else false
    seed = derive_key { key : @seed, @who, which : "EdDSA", omit_prefix, alg }
    await KeyManager.generate { seed }, esc defer @kms.signing
    seed = derive_key { key : @seed, @who, which : "DH", omit_prefix, alg }
    await EncKeyManager.generate { seed }, esc defer @kms.encryption
    @secret_box_key = derive_key { key : @seed, @who, which : "SecretBox", omit_prefix, alg }
    cb null

##=======================================================================

exports.PerUserSecretKeys = class PerUserSecretKeys extends PerXSecretKeys
  constructor : (args) ->
    args.who = "User"
    super args

##=======================================================================

exports.PerTeamSecretKeys = class PerTeamSecretKeys extends PerXSecretKeys
  constructor : (args) ->
    args.who = "Team"
    super args

  @make : ({prng}, cb) ->
    s = new PerTeamSecretKeys {prng}
    await s.derive {}, defer err
    cb err, s

##=======================================================================

# PerTeamSecretKeySet corresponds to what's uploaded to the sig/multi endpoint with
#  the per_team_secrets parameter.  This class is used for both parsing that parameter
#  (via s_parse + prepare), or for creating a new set of encrypted secret keys
#  in test (via encrypt).
exports.PerTeamSecretKeySet = class PerTeamSecretKeySet

  constructor : ({@encrypting_km, @generation, @boxes, @prev, @encrypting_kid, @nonce, @prng}) ->

  #-----

  prepare : (opts, cb) ->
    esc = make_esc cb, "prepare"
    await kbpgp.kb.EncKeyManager.import_public { hex }, esc defer @encrypting_km if (hex = @encrypting_kid)?
    cb null

  #-----

  to_proof_arg : ({ptsk_new}) ->

    encryption_kid = ptsk_new.get_kms().encryption.get_ekid().toString('hex')
    signing_kid = ptsk_new.get_kms().signing.get_ekid().toString('hex')
    new PerTeamPublicKeySet { @generation, encryption_kid, signing_kid }

  #-----

  eq : (ks2) ->
    if @encrypting_km and ks2.encrypting_km
      return false unless (@encrypting_km.eq(ks2.encrypting_km) and
        (@generation is ks2.generation) and
          @boxes.eq(ks2.boxes))
    else if @encrypting_km? or ks2.encrypting_km?
      return false
    if @prev? and ks2.prev?
      return false unless bufeq_secure(@prev, ks2.prev)
    else if @prev? or ks2.prev?
      return false
    if @nonce? and ks2.nonce?
      return false unless @nonce.top_eq(ks2.nonce)
    else if @nonce? or ks2.nonce?
      return false
    return true

  #-----

  get_boxes : () -> if @boxes? then @boxes.boxes() else []

  #-----

  # encrypt takes the current PerTeamSecretKeys and the previous,
  # and encrypts both for all of the members in the team. The previous
  # key set is encrypted via the prev-chaining system
  #
  # @param {PerTeamSecretKeys} ptsk_new The new per team key set
  # @param {PerTeamSecretKeys} ptsk_prev The previous per team key set
  encrypt : ({ptsk_new, ptsk_prev}, cb) ->
    esc = make_esc cb, "PerTeamSecretKeySet.encrypt"
    @nonce = nonce = new Nonce20 {@prng}
    enc = 'base64'
    out =
      generation : @generation
      encrypting_kid : @encrypting_km.get_ekid().toString('hex')
      nonce : nonce.get_top().toString(enc)
    if ptsk_prev?
      encryptor = nacl.alloc { secretKey : ptsk_new.get_secret_box_key() }
      ctext = encryptor.secretbox({plaintext : ptsk_prev.get_seed(), nonce : nonce.buffer() })
      # As in per-user prevs, encode the prev secret box
      # as pack [ 1, <nonce>, <secretbox> ]
      @prev = pack([1, nonce.buffer(), ctext])
      out.prev = @prev.toString(enc)
    nonce = nonce.next()
    await @boxes.encrypt { @encrypting_km, nonce, per_team_key : ptsk_new.get_seed(), enc }, esc defer out.boxes
    cb null, out

##=======================================================================

exports.PerTeamKeyBox = class PerTeamKeyBox

  constructor : ({@uid, @per_user_key_seqno, @nonce_bottom, @box, @km}) ->

  @parse_throw : ({uid, box}) ->
    v = unpack Buffer.from(box, 'base64')
    if v.length isnt 4
      throw MBPTKE("needed 4 elements in box for #{uid}; got #{v.length}")
    if v[0] isnt 1
      throw MBPTKE("can only handle version=1; got #{v[0]}")
    if typeof(v[1]) isnt 'number' or v[1] <= 0
      throw MBPTKE("can only handle positive per_user_key_seqnos, got #{v[1]}")
    if typeof(v[2]) isnt 'number' or v[2] <= 0
      throw MBPTKE("can only handle positive nonce bottoms, got #{v[2]}")
    return new PerTeamKeyBox { uid, per_user_key_seqno : v[1], nonce_bottom : v[2], box : v[3] }

  eq : (skb2) ->
    ret = (@uid is skb2.uid) and \
       (@per_user_key_seqno is skb2.per_user_key_seqno) and \
       (@nonce_bottom is skb2.nonce_bottom) and \
       bufeq_secure(@box, skb2.box)
    ret

  export_ctext : () -> @box.toString('base64')

  encrypt : ({encrypting_km,nonce,per_team_key,enc}, cb) ->
    esc = make_esc cb, "PerTeamKeyBox.encrypt"
    await kb.box { sign_with : encrypting_km, nonce : nonce.buffer(), encrypt_for : @km, msg : per_team_key }, esc defer box
    @box = (unpack Buffer.from(box, 'base64')).body.ciphertext
    @nonce_bottom = nonce.get_bottom()
    cb null, @pack(enc)

  pack : (enc) -> pack([1, @per_user_key_seqno, @nonce_bottom, @box]).toString(enc)

##=======================================================================

exports.PerTeamKeyBoxes = class PerTeamKeyBoxes

  constructor : (@d) ->
    @d or= {}

  eq : (skb2) ->
    for k,v of @d
      return false unless (v2 = skb2.d[k])? and v.eq(v2)
    for k2,v2 of skb2.d
      return false unless (v = @d[k2])? and v.eq(v2)
    return true

  boxes : () -> (v for _, v of @d)

  # @param {PerTeamKeyBox} b The perTeamKeyBox to add
  add : (b) -> @d[b.uid] = b

  encrypt : ({encrypting_km,nonce,per_team_key,enc}, cb) ->
    esc = make_esc cb, "PerTeamKeyBoxes.encrypt"
    out = {}
    for k,v of @d
      await v.encrypt {encrypting_km, nonce, per_team_key,enc}, esc defer out[k]
      nonce = nonce.next()
    cb null, out

##=======================================================================

exports.Nonce20 = class Nonce20

  constructor : ({@top,@i,@prng}) ->
    @top or= @prng(20)
    @i or= 0

  next : () -> new Nonce20 { @top, i : @i + 1}

  at : (i) -> new Nonce20 { @top, i : i}

  buffer : () ->
    bottom = Buffer.alloc(4)
    bottom.writeUInt32BE(@i, 0)
    Buffer.concat [ @top, bottom ]

  get_top : () -> @top
  get_bottom : () -> @i

  top_eq : (n2) -> bufeq_secure @top, n2.top

##=======================================================================

exports.RatchetBlindingKey = class RatchetBlindingKey

  constructor : ({@version, @ratchet, @blinding_key, @link_id, @seqno, @chain_type}) ->

  encode_body : () -> { h : @link_id, s : @seqno, t : @chain_type }
  encode_ratchet : () -> { k : @blinding_key, r : @ratchet }
  encode : () -> { b : @encode_body(), r : @encode_ratchet(), v : @version }

  @generate : ({link_id, seqno, chain_type, prng}) ->
    blinding_key = prng(32)
    ret = new RatchetBlindingKey { blinding_key, link_id, version : 1, seqno, chain_type }
    ret.ratchet = ret.compute()
    return ret

  compute : () ->
    h = createHmac 'sha512', @blinding_key
    h.update pack @encode_body()
    # should equal 'ratchet' when passed in
    ret = h.digest()[0...32]
    ret

  id : () -> @ratchet.toString('hex')

##=======================================================================

exports.RatchetBlindingKeySet = class RatchetBlindingKeySet

  constructor : ({@d}) ->

  @generate : (ratchets) ->
    d = {}
    for r in ratchets
      d[r.id()] = r
    return new RatchetBlindingKeySet { d }

  encode : () ->
    arr = (v.encode() for _, v of @d)
    return pack(arr).toString('base64')
