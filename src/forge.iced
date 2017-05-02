
{make_esc} = require 'iced-error'
{athrow,akatch,unix_time} = require('iced-utils').util
kbpgp = require 'kbpgp'
proofs = require 'keybase-proofs'
{prng,createHash} = require 'crypto'
btcjs = require 'keybase-bitcoinjs-lib'

#===================================================

UID_HEX_LEN = 32
UID_SUFFIX = "19"

username_to_uid = (un) ->
  hashlen = UID_HEX_LEN - 2
  return createHash('sha256').update(un).digest('hex').slice(0, hashlen) + UID_SUFFIX

#===================================================

# most of this copy-pasted from keybase-proofs, but I didn't want to
# introduce this code into that repo, since it's only for crafting
# malicious proofs -- MK 2017/4/3
generate_v2_with_corruption = ({proof, opts, hooks}, cb) ->
  esc = make_esc cb, "generate"
  out = null
  await proof._v_generate {}, esc defer()
  generate_inner_arg = { version : 2 }
  hooks.pre_generate_inner? { generate_inner_arg }
  await proof.generate_json generate_inner_arg, esc defer s, o
  inner = { str : s, obj : o }
  hooks.pre_generate_outer? { proof, inner }
  await proof.generate_outer {inner }, esc defer outer
  hooks.post_generate_outer? { proof, outer, inner }
  await proof.sig_eng.box outer, esc defer {pgp, raw, armored}
  hooks.corrupt_box? { inner, outer, pgp, raw, armored }
  {short_id, id} = proofs.make_ids raw
  out = { inner, outer, pgp, raw, armored, short_id, id }
  hooks.corrupt_ids? out
  cb null, out

#===================================================

generate_proof = ({proof, linkdesc}, cb) ->
  if (hooks = linkdesc.corrupt_v2_proof_hooks)?
    generate_v2_with_corruption { proof, opts : {}, hooks }, cb
  else
    proof.generate_versioned { version : linkdesc.version}, cb

#===================================================

class Key

  constructor : ({@km, @expire_in, @ctime, @revoked_at}) ->

  get_kid : () -> @km.get_ekid().toString 'hex'

#===================================================

SIG_ID_SUFFIX = "0f"

class Link

  constructor : ( {@linkdesc, @proof, @generate_res}) ->

  inner_payload_json_str : () -> @generate_res.json or @generate_res.inner.str

  get_payload_hash : () ->
    createHash('sha256').update(@generate_res.outer or @inner_payload_json_str()).digest('hex')

  get_sig_id : () -> @generate_res.id + SIG_ID_SUFFIX

  to_json_full : () -> {
    seqno : @proof.seqno
    prev : @proof.prev
    sig : @generate_res.armored
    payload_hash : @get_payload_hash()
    sig_id : @get_sig_id()
    payload_json : @inner_payload_json_str()
    kid: @proof.sig_eng.get_km().get_ekid().toString("hex")
    ctime: @proof.ctime
    sig_version : @linkdesc.version
  }

  to_json : () ->
    if (@linkdesc.version is 2) and @linkdesc.stubbed then @to_json_stubbed()
    else @to_json_full()

  to_json_stubbed : () -> {
    s2 : @generate_res.outer.toString('base64')
  }

#===================================================

class Keyring

  constructor : () ->
    @bundles = []
    @label = {}

  to_json : () ->
    # A list of bundles allows most callers to just use the first bundle as the
    # eldest key. Tests involving a chain reset will need to know what key
    # index they want, but they still won't need to hardcode the eldest key.
    # Also callers should be computing KIDs themselves, so they don't need a
    # map.
    @bundles

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

  _make_key : ({km, obj}, cb) ->
    esc = make_esc cb, "_make_key"
    k = new Key { km, ctime : @_compute_now(), expire_in : @_get_expire_in({obj}) }
    await km.export_public { regen: true }, esc defer bundle
    @_keyring.bundles.push(bundle)
    @_keyring.label[obj.label] = k
    cb null, k

  #-------------------

  _compute_time_or_default : (linkdesc, field) ->
    if field?
      @_compute_time(field)
    else
      linkdesc.ctime

  #-------------------

  _compute_time : (o, advance=false) ->
    # Only advance time if `advance` argument is true. We want to only
    # advance time when processing links' ctime, not every time we
    # deal with a time field, so one link advances time at most one
    # time.

    ret = if typeof(o) is 'string'
      if o is 'now' then @_compute_now()
      else if not (m = o.match /^([\+-])?(\d+)$/) then null
      else if m[1]?
        if m[1] == '+'
          tmp = @_compute_now() + parseInt(m[2])
          @_now = tmp if advance
        else
          tmp = @_compute_now() - parseInt(m[2])

        tmp
      else
        tmp = parseInt(m[2])
        @_now = tmp if advance
        tmp
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
      @_start = if (t = @get_chain().ctime)? then @_compute_time(t, true) else @_compute_now()
      @_expire_in = @get_chain().expire_in or 60*60*24*364*10
      @_username = @get_chain().user or "tester_ralph"
      @_uid = @get_chain().uid or username_to_uid @_username
    catch e
      err = e
    cb err

  #-------------------

  _forge_link : ({linkdesc}, cb) ->
    # Compute time at the very beginning of link forging. Other
    # parameters of the link might want to use "current time".
    linkdesc.ctime = if (t = linkdesc.ctime)? then @_compute_time(t, true) else @_compute_now()

    # Use v=1 by default, but allow for v=2 and whatever else
    linkdesc.version = if (v = linkdesc.version)? then v else 1

    switch linkdesc.type
      when 'eldest'     then @_forge_eldest_link     {linkdesc}, cb
      when 'subkey'     then @_forge_subkey_link     {linkdesc}, cb
      when 'sibkey'     then @_forge_sibkey_link     {linkdesc}, cb
      when 'revoke'     then @_forge_revoke_link     {linkdesc}, cb
      when 'track'      then @_forge_track_link      {linkdesc}, cb
      when 'pgp_update' then @_forge_pgp_update_link {linkdesc}, cb
      when 'btc'        then @_forge_btc_link        {linkdesc}, cb
      else cb (new Error "unhandled link type: #{linkdesc.type}"), null

  #-------------------

  _gen_key : ({obj, required}, cb) ->
    userid = obj.userid or @_username

    esc = make_esc cb, "_gen_key"
    if (typ = obj.key?.gen)?
      switch typ
        when 'eddsa'
          await kbpgp.kb.KeyManager.generate {}, esc defer km
        when 'dh'
          await kbpgp.kb.EncKeyManager.generate {}, esc defer km
        when 'pgp_rsa'
          await kbpgp.KeyManager.generate_rsa { userid : userid }, esc defer km
          await km.sign {}, esc defer()
        when 'pgp_ecc'
          t = @_compute_time_or_default obj, obj.key.generated
          await kbpgp.KeyManager.generate_ecc { userid : userid, generated: t, expire_in: { primary: obj.key.expire_in } }, esc defer km
          await km.sign {}, esc defer()
        else
          await athrow (new Error "unknown key type: #{typ}"), defer()
    else if required
      await athrow (new Error "Required to generate key but none found"), defer()
    key = null
    if km?
      await @_make_key {km, obj}, esc defer key
    cb null, key

  #-------------------

  _populate_proof : ({linkdesc, proof}) ->
    proof.seqno = linkdesc.seqno or @_seqno++
    proof.prev = linkdesc.prev or @_prev
    proof.host = "keybase.io"
    proof.user =
      local :
        uid : linkdesc.uid or @_uid
        username : linkdesc.username or @_username
    proof.seq_type = proofs.constants.seq_types.PUBLIC
    proof.ctime = linkdesc.ctime # Was already converted to "real time" in _forge_link
    proof.expire_in = @_get_expire_in { obj : linkdesc }

  #-------------------

  _forge_eldest_link : ({linkdesc}, cb) ->
    esc = make_esc cb, "_forge_eldest_link"
    await @_gen_key { obj : linkdesc, required : true }, esc defer key
    proof = new proofs.Eldest {
      sig_eng : key.km.make_sig_eng()
    }
    await @_sign_and_commit_link { linkdesc, proof }, esc defer()
    @_eldest_kid = key.km.get_ekid().toString 'hex'
    cb null

  #-------------------

  _forge_subkey_link : ({linkdesc}, cb) ->
    esc = make_esc cb, "_forge_subkey_link"
    await @_gen_key { obj : linkdesc, required : true }, esc defer key
    parent = @_keyring.label[(ref = linkdesc.parent)]
    unless parent?
      err = new Error "Unknown parent '#{ref}' in link '#{linkdesc.label}'"
      await athrow err, esc defer()
    proof = new proofs.Subkey {
      subkm : key.km
      sig_eng : parent.km.make_sig_eng()
      parent_kid : parent.km.get_ekid().toString 'hex'
      eldest_kid : @_eldest_kid
    }
    await @_sign_and_commit_link { linkdesc, proof }, esc defer()
    cb null

  #-------------------

  _forge_sibkey_link : ({linkdesc}, cb) ->
    esc = make_esc cb, "_forge_sibkey_link"
    await @_gen_key { obj : linkdesc, required : true }, esc defer key
    signer = @_keyring.label[(ref = linkdesc.signer)]
    unless signer?
      err = new Error "Unknown signer '#{ref}' in link '#{linkdesc.label}'"
      await athrow err, esc defer()
    proof = new proofs.Sibkey {
      sibkm : key.km
      sig_eng : signer.km.make_sig_eng()
      eldest_kid : @_eldest_kid
    }
    await @_sign_and_commit_link { linkdesc, proof }, esc defer()
    cb null

  #-------------------

  _forge_track_link : ({linkdesc}, cb) ->
    esc = make_esc cb, "_forge_sibkey_link"
    signer = @_keyring.label[(ref = linkdesc.signer)]
    unless signer?
      err = new Error "Unknown signer '#{ref}' in link '#{linkdesc.label}'"
      await athrow err, esc defer()
    proof = new proofs.Track {
      eldest_kid : @_eldest_kid
      sig_eng : signer.km.make_sig_eng()
      track : {"basics":{"id_version":1,"last_id_change":1424384373,"username":"t_doug"},"id":"c4c565570e7e87cafd077509abf5f619","key":{"key_fingerprint":"23f9d8552c5d419976a8efdac11869d5bc47825f","kid":"0101bdda803b93cd728b21c588c77549e5dca960d4bcc589b4b80162ecc82f3c283b0a"},"pgp_keys":[{"key_fingerprint":"23f9d8552c5d419976a8efdac11869d5bc47825f","kid":"0101bdda803b93cd728b21c588c77549e5dca960d4bcc589b4b80162ecc82f3c283b0a"}],"remote_proofs":[],"seq_tail":null}
    }
    await @_sign_and_commit_link { linkdesc, proof }, esc defer()
    cb null

  #-------------------

  _forge_btc_link : ({linkdesc}, cb) ->
    esc = make_esc cb, "_forge_sibkey_link"
    signer = @_keyring.label[(ref = linkdesc.signer)]
    unless signer?
      err = new Error "Unknown signer '#{ref}' in link '#{linkdesc.label}'"
      await athrow err, esc defer()

    arg = {
      sig_eng : signer.km.make_sig_eng()
      cryptocurrency :
        type : "bitcoin"
        address : (new btcjs.Address prng(20), 0).toBase58Check()
      eldest_kid : @_eldest_kid
    }
    revoke = {}
    if linkdesc.revoke?
      await @_forge_revoke_section { revoke, linkdesc }, esc defer()
      arg.revoke = revoke
    proof = new proofs.Cryptocurrency arg
    await @_sign_and_commit_link { linkdesc, proof }, esc defer()
    cb null

  #-------------------

  _forge_revoke_link : ({linkdesc}, cb) ->
    esc = make_esc cb, "_forge_sibkey_link"
    signer = @_keyring.label[(ref = linkdesc.signer)]
    unless signer?
      err = new Error "Unknown parent '#{ref}' in link '#{linkdesc.label}'"
      await athrow err, esc defer()
    revoke = {}
    args = {
      sig_eng : signer.km.make_sig_eng(),
      eldest_kid : @_eldest_kid
      revoke
    }
    if (raw = linkdesc.revoke.raw)?
      args.revoke = raw
    else
      await @_forge_revoke_section { linkdesc, revoke }, esc defer()
    proof = new proofs.Revoke args
    await @_sign_and_commit_link { linkdesc, proof }, esc defer()
    cb null

  #-------------------

  _forge_revoke_section : ({linkdesc, revoke}, cb) ->
    err = null
    errs = []
    if (key = linkdesc.revoke.key)?
      unless (revoke.kid = @_keyring.label[key]?.get_kid())?
        err = new Error "Cannot find key '#{key}' to revoke in link '#{linkdesc.label}'"
    else if (arr = linkdesc.revoke.keys)?
      revoke.kids = []
      for a in arr
        if (k = @_keyring.label[a]?.get_kid())?
          revoke.kids.push k
        else
          errs.push "Failed to find revoke key '#{a}' in link '#{linkdesc.label}'"
    else if (label = linkdesc.revoke.sig)?
      unless (revoke.sig_id = @_link_tab[label]?.get_sig_id())?
        err = new Error "Cannot find sig '#{label}' in link '#{linkdesc.label}'"
    else if (sigs = linkdesc.revoke.sigs)?
      revoke.sig_ids = []
      for label in sigs
        if (id = @_link_tab[label]?.get_sig_id())?
          revoke.sig_ids.push id
        else
          errs.push "Failed to find sig '#{label}' in link '#{linkdesc.label}'"
    if errs.length
      err = new Error errs.join "; "
    cb err

  #-------------------

  _forge_pgp_update_link : ({linkdesc}, cb) ->
    esc = make_esc cb, "_forge_pgp_update_link"

    key = @_keyring.label[linkdesc.pgp_update_key]

    proof = new proofs.PGPUpdate {
      sig_eng : @_keyring.label[linkdesc.signer].km.make_sig_eng()
      pgpkm : key.km
      eldest_kid : @_eldest_kid
    }

    # Remember current ekid to compare after updates. Our updates
    # should not change ekid.
    old_ekid = key.km.get_ekid()

    lifespan = key.km.primary.lifespan
    lifespan.expire_in = linkdesc.key_expire_in
    lifespan.generated = @_compute_time linkdesc.generated if linkdesc.generated?

    if uid = linkdesc.userid
      key.km.userids[0] = new kbpgp.opkts.UserID(uid)

    key.km.clear_pgp_internal_sigs()

    await key.km.sign {}, esc defer()
    await @_make_key { obj: linkdesc, km: key.km }, esc defer key

    await @_sign_and_commit_link { linkdesc, proof }, esc defer()

    unless key.km.get_ekid().equals(old_ekid)
      await athrow new Error('update failed : different ekid'), esc defer()

    cb null

  #-------------------

  _sign_and_commit_link : ({linkdesc, proof}, cb) ->
    esc = make_esc cb, "_sign_and_commit_link"
    @_populate_proof { linkdesc, proof }
    await generate_proof { proof, linkdesc }, esc defer generate_res
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
    if @chain.keys?
      for name, parts of @chain.keys
        if parts.gen
          await @_gen_key { obj: parts.gen }, esc defer()
        else
          await kbpgp.KeyManager.import_from_armored_pgp { armored : parts.public }, esc defer km
          await km.merge_pgp_private { armored : parts.private }, esc defer()
          k = new Key { km, ctime : @_compute_now(), expire_in : @_expire_in }
          @_keyring.bundles.push parts.public
          @_keyring.label[name] = k
    for linkdesc in @get_chain().links
      await @_forge_link { linkdesc }, esc defer out
    label_kids = {}
    for label, key of @_keyring.label
      label_kids[label] = key.km.get_ekid().toString "hex"
    label_sigs = {}
    for label, link of @_link_tab
      label_sigs[label] = link.get_sig_id()
    ret =
      chain : (link.to_json() for link in @_links)
      keys : @_keyring.to_json()
      uid : @_uid
      username : @_username
      label_kids : label_kids
      label_sigs : label_sigs
    cb null, ret

#===================================================

