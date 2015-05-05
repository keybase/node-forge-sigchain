
{make_esc} = require 'iced-error'
{akatch,unix_time} = require('iced-utils').util
kbpgp = require 'kbpgp'
proofs = require 'keybase-proofs'
{createHash} = require 'crypto'

#===================================================

username_to_uid = (un) ->
  return createHash('sha256').update(un).digest('hex') + "19"

#===================================================

class Key

  constructor : ({@km, @expire_in, @ctime, @revoked_at}) ->

  get_kid : () -> @km.get_ekid().toString 'hex'

#===================================================

class Link

  constructor : ( {@linkdesc, @proof, @generate_res}) ->

  get_payload_hash : () -> createHash('sha256').update(@generate_res.json).digest('hex')

  get_sig_id : () -> @generate_res.id

  to_json : () -> {
    seqno : @proof.seqno
    prev : @proof.prev
    sig : @generate_res.armored
    payload_hash : @get_payload_hash()
    sig_id : @generate_res.id
    payload_json : @generate_res.json
  }

#===================================================

class Keyring

  constructor : () ->
    @kid = {}
    @label = {}

  to_json : (cb) ->
    esc = make_esc cb, "to_json"
    out = {}
    for kid, key of @kid
      await key.km.export_public {}, esc defer bundle
      out[kid] = bundle
    cb null, out

#===================================================

exports.Forge = class Forge

  #-------------------

  constructor : ({@chain}) ->
    @_keyring = new Keyring
    @_links = []
    @_link_tab = {}
    @_assertions = []
    @_time = 0
    @_start = null
    @_now = null
    @_expire_in = 0
    @_seqno = 1
    @_prev = null
    @_username = null

  #-------------------

  _compute_now : () ->
    @_now = unix_time() unless @_now?
    @_now

  #-------------------

  _get_expire_in : ({obj}) -> (obj.expire_in or @_expire_in)

  #-------------------

  _make_key : ({km, obj}) ->
    k = new Key { km, ctime : @_compute_now(), expire_in : @_get_expire_in({obj}) }
    @_keyring.kid[km.get_ekid().toString('hex')] =  k
    @_keyring.label[obj.label] = k
    k

  #-------------------

  _compute_time : (o) ->
    ret = if typeof(o) is 'string'
      if o is 'now' then @_compute_now()
      else if not (m = o.match /^(\+)?(\d+)$/) then null
      else if m[1]?
        tmp = @_compute_now() + parseInt(m[2])
        @_now = tmp
        tmp
      else
        parseInt(m[2])
    else if typeof(o) isnt 'object' then null
    else if o.sum?
      sum = 0
      for term in o.sum
        sum += @_compute_time(term)
      sum
    else null
    throw new Error "bad time: #{JSON.stringify o}" unless ret?
    ret

  #-------------------

  _init : (cb) ->
    try
      @_start = if (t = @get_chain().time)? then @_compute_time(t) else @_compute_now()
      @_expire_in = @get_chain().expire_in or 60*60*24*364*10
      @_username = @get_chain().user or "tester_ralph"
      @_uid = @get_chain().uid or username_to_uid @_username
    catch e
      err = e
    cb err

  #-------------------

  _forge_link : ({linkdesc}, cb) ->
    switch linkdesc.type
      when 'eldest' then @_forge_eldest_link {linkdesc}, cb
      when 'subkey' then @_forge_subkey_link {linkdesc}, cb
      when 'sibkey' then @_forge_sibkey_link {linkdesc}, cb
      when 'revoke' then @_forge_revoke_link {linkdesc}, cb
      else cb (new Error "unhandled link type: #{linkdesc.type}"), null

  #-------------------

  _gen_key : ({obj, required}, cb) ->
    esc = make_esc cb, "_gen_key"
    err = null
    if (typ = obj.key?.gen)?
      switch typ
        when 'eddsa'
          await kbpgp.kb.KeyManager.generate {}, esc defer km
        when 'dh'
          await kbpgp.kb.EncKeyManager.generate {}, esc defer km
        when 'pgp_rsa'
          await kbpgp.KeyManager.generate_rsa { userid : @_username }, esc defer km
          await km.sign {}, esc defer()
        when 'pgp_ecc'
          await kbpgp.KeyManager.generate_ecc { userid : @_username }, esc defer km
          await km.sign {}, esc defer()
        else
          err = new Error "unknown key type: #{typ}"
    else if required then err = new Error "Required to generate key but none found"
    key = if km? and not err? then @_make_key {km, obj} else null
    cb err, key

  #-------------------

  _populate_proof : ({linkdesc, proof}) ->
    proof.seqno = @_seqno++
    proof.prev = @_prev
    proof.host = "keybase.io"
    proof.user =
      local :
        uid : @_uid
        username : @_username
    proof.seq_type = proofs.constants.seq_types.PUBLIC
    proof.ctime = if (t = linkdesc.ctime)? then @_compute_time(t) else @_compute_now()
    proof.expire_in = @_get_expire_in { obj : linkdesc }

  #-------------------

  _forge_eldest_link : ({linkdesc}, cb) ->
    esc = make_esc cb, "_forge_eldest_link"
    await @_gen_key { obj : linkdesc, required : true }, esc defer key
    proof = new proofs.Eldest {
      sig_eng : key.km.make_sig_eng()
    }
    await @_sign_and_commit_link { linkdesc, proof }, esc defer()
    cb null

  #-------------------

  _forge_subkey_link : ({linkdesc}, cb) ->
    esc = make_esc cb, "_forge_subkey_link"
    await @_gen_key { obj : linkdesc, required : true }, esc defer key
    parent = @_keyring.label[linkdesc.parent]
    proof = new proofs.Subkey {
      subkm : key.km
      sig_eng : parent.km.make_sig_eng()
      parent_kid : parent.km.get_ekid().toString 'hex'
    }
    await @_sign_and_commit_link { linkdesc, proof }, esc defer()
    cb null

  #-------------------

  _forge_sibkey_link : ({linkdesc}, cb) ->
    esc = make_esc cb, "_forge_sibkey_link"
    await @_gen_key { obj : linkdesc, required : true }, esc defer key
    signer = @_keyring.label[linkdesc.signer]
    proof = new proofs.Sibkey {
      sibkm : key.km
      sig_eng : signer.km.make_sig_eng()
    }
    await @_sign_and_commit_link { linkdesc, proof }, esc defer()
    cb null

  #-------------------

  _forge_revoke_link : ({linkdesc}, cb) ->
    esc = make_esc cb, "_forge_sibkey_link"
    signer = @_keyring.label[linkdesc.signer]
    revoke = {}
    args = {
      sig_eng : signer.km.make_sig_eng(),
      revoke
    }
    if (key = linkdesc.revoke.key)?
      revoke.kid = @_keyring.label[key].get_kid()
    else if (arr = linkdesc.revoke.keys)?
      revoke.kids = []
      for a in arr when (k = @_keyring.label[a].get_kid())?
        revoke.kids.push k
    else if (sig_id = linkdesc.revoke.sig)?
      revoke.sig_id = @_link_tab[sig_id].get_sig_id()
    proof = new proofs.Revoke args
    await @_sign_and_commit_link { linkdesc, proof }, esc defer()
    cb null

  #-------------------

  _sign_and_commit_link : ({linkdesc, proof}, cb) ->
    esc = make_esc cb, "_sign_and_commit_link"
    @_populate_proof { linkdesc, proof }
    await proof.generate esc defer generate_res
    link = new Link { linkdesc, proof, generate_res }
    @_prev = link.get_payload_hash()
    @_links.push link
    @_link_tab[linkdesc.label] = link
    cb null

  #-------------------

  get_chain : () -> @chain

  #-------------------

  forge : (cb) ->
    esc = make_esc cb, "Forge::forge"
    await @_init esc defer()
    for linkdesc in @get_chain().links
      await @_forge_link { linkdesc }, esc defer out
    await @_keyring.to_json esc defer keys
    ret =
      chain : (link.to_json() for link in @_links)
      keys : keys
    cb null, ret

#===================================================

