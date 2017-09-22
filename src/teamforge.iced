{make_esc} = require 'iced-error'
{athrow,akatch,unix_time} = require('iced-utils').util
kbpgp = require 'kbpgp'
proofs = require 'keybase-proofs'
constants = proofs.constants
{prng,createHash} = require 'crypto'
{make_prng} = require './badprng'
{PerUserSecretKeys, PerTeamSecretKeys, PerTeamKeyBoxes, PerTeamSecretKeySet, PerTeamKeyBox} = require './teamlib'

#===================================================

assert = (condition, msg) ->
  unless condition
    throw new Error msg

#===================================================

exports.TeamForge = class TeamForge

  #-------------------

  constructor : ({@chain}) ->

  #-------------------

  forge : (cb) ->
    esc = make_esc cb, "TeamForge::forge"

    # initialize a deterministic prng
    # so that the generated json is more likely to be deterministic
    @prng = make_prng()
    # temporary state for the forge
    @teams = {}
    @users = {}
    # return value for the forge
    @out =
      log: []
      teams: {}
      users: {}
      key_owners: {} # map from keyid to user_label
      key_pubkeyv2nacls: {} # map from keyid to keybase1.PublicKeyV2NaCl's
      # map from team id to {seqno, linkid}
      # also map from "<teamid>-seqno:<seqno>"
      # This is part of the fake merkle tree that is represented in the test outputs.
      # It is consumed by the Go test driver mock in the client-side tests
      # and used to return team merkle leafs to the client code being tested.
      team_merkle: {}
      merkle_triples: {} # map from keys with a dash "LeafID-HashMeta" to MerkleTriple's
      sessions: @chain.sessions
    @_link_id_gen = new LinkIDGen

    # This is the user who is loading teams.
    # They are also the default for forging actions when no one else is specified.
    @default_user_label = "herb"

    for user_label, user_desc of @chain.users
      await User.make {forge:@, label: user_label, user_desc}, esc defer user
      @users[user_label] = user
      await user.apply @out, esc defer()

    for label, team_desc of @chain.teams
      await Team.make {forge:@, label}, esc defer team
      @teams[label] = team

      for link_desc in team_desc.links
        @push_log "link team:#{label} type:#{link_desc.type}"
        user = @users[link_desc.signer or @default_user_label]
        assert user?, "signing user '#{link_desc.signer}'"
        await team.forge_link {link_desc, user}, esc defer()

      await team.apply @out, esc defer()

    cb null, @out

  #-------------------

  push_log : (x) ->
    @out.log.push x

  #-------------------

  _hash_meta : (number) ->
    base = "cd".repeat 32
    num_str = number.toString()
    (base[...-num_str.length] + num_str)

  #-------------------

  _gen_key : (typ, cb) ->
    switch typ
      when 'eddsa'
        kbpgp.kb.KeyManager.generate {seed: @prng 32}, cb
      when 'dh'
        kbpgp.kb.EncKeyManager.generate {seed: @prng 32}, cb
      else
        await athrow (new Error "unknown key type: #{typ}"), defer()

#===================================================

class LinkIDGen
  constructor : () ->
    @n = 0

  next_link_id : () ->
    base = "ef".repeat 32
    num_str = (@n++).toString()
    (base[...-num_str.length] + num_str)

#===================================================

class User
  @make : (args, cb) ->
    obj = new User args
    obj._init (err) -> cb err, obj

  #-------------------

  constructor : ({@forge, @label, @user_desc, @username, @eldest_seqno}) ->
    # pass

  #-------------------

  _init : (cb) ->
    esc = make_esc cb, "TeamForge::User::_init"

    @username or= @label
    @eldest_seqno or= 1
    @uid = @_gen_uid {@label}
    @keys = {} # label -> keypair

    @user_desc.keys or= {}
    @user_desc.keys["default"] or= {}
    for key_label, key_desc of @user_desc.keys
      @forge.push_log "user:#{@label} key:#{key_label}"
      # generate an eldest key
      await @forge._gen_key 'eddsa', esc defer km_sig
      await @forge._gen_key 'dh', esc defer km_enc
      pubkeyv2nacl = 
        deviceType: "desktop"
        deviceDescription: "home thing"
        deviceID: "fbd762facdfad44709aef63a9a8cdf18"
        base:
          eTime: 2005146762000
          cTime: 1500570762000
          isEldest: true
          isSibkey: true
          kid: km_sig.get_ekid().toString "hex"
      pubkeyv2nacl.base.provisioning =
        sigChainLocation:
          seqno: 1
          seqType: 1 # public
        signingKID: km_sig.get_ekid().toString "hex"
        time: 0
        firstAppearedUnverified: 0
        prevMerkleRootSigned:
          hashMeta: @forge._hash_meta 500
          seqno: 0
      if key_desc.revoke?
        pubkeyv2nacl.base.revocation =
          sigChainLocation:
            seqno: key_desc.revoke.seqno
            seqType: 1 # public
          signingKID: km_sig.get_ekid().toString "hex"
          prevMerkleRootSigned:
            hashMeta: @forge._hash_meta key_desc.revoke.merkle_hashmeta
            seqno: 0
          time: 0
          firstAppearedUnverified: 0
      @keys[key_label] =
        signing: km_sig
        encryption: km_enc
        pubkeyv2nacl: pubkeyv2nacl

    @puk_secrets =
      1: @forge.prng(32).toString('hex')
      # 1: "5b7923a534415f19ac4f5c97f32605f1b542bcf5f134b57241dee2b790c09648"

    @link_map =
      1: @forge._link_id_gen.next_link_id()

    cb null

  #-------------------

  # Impose upon the forge output.
  apply : (out, cb) ->
    esc = make_esc cb, "User::apply"

    await @get_puk_kms esc defer puk_kms
  
    out.users[@label] =
      uid: @uid
      eldest_seqno: @eldest_seqno
      puk_secrets: @puk_secrets
      link_map: @link_map
      debug_puk_enc_kid: puk_kms.encryption.get_ekid().toString 'hex'

    for label, keys of @keys
      kid = keys.signing.get_ekid().toString "hex"
      out.key_owners[kid] = @label
      out.key_pubkeyv2nacls[kid] = keys.pubkeyv2nacl

    cb null

  #-------------------

  get_puk_kms : (cb) ->
    esc = make_esc cb, "User::get_puk_kms"
    s = new PerUserSecretKeys { seed: (new Buffer @puk_secrets[1], 'hex'), prng: @forge.prng }
    await s.derive {}, esc defer()
    cb null, s.kms

  #-------------------

  uv_str : () ->
    if @eldest_seqno isnt 1
      "#{@uid}%#{eldest_seqno}"
    else
      @uid

  #-------------------

  _gen_uid : ({label}) ->
    h = (SHA256 label)[0...15]
    id = h.toString('hex') + "19"
    return id

#===================================================

class Team
  @make : (args, cb) ->
    obj = new Team args
    obj._init (err) -> cb err, obj

  #-------------------

  constructor: ({@forge, @label, @name}) ->
    # pass

  #-------------------

  _init: (cb) ->
    esc = make_esc cb, "Team::_init"
    @name or= @label
    @id = @_hash_team_id @name
    @ptsks_list = []
    @team_key_boxes = []
    @links = []
    cb null

  #-------------------

  # Impose upon the forge output.
  apply : (out, cb) ->
    esc = make_esc cb, "Team::apply"

    out.teams[@label] =
      id: @id
      links: (link.for_client for link in @links)
      team_key_boxes: @team_key_boxes
      debug_tk_secs: [(ptsk.seed.toString 'hex') for ptsk in @ptsks_list]
      debug_tk_sig_kids: [(ptsk.kms.signing.get_ekid().toString 'hex') for ptsk in @ptsks_list]

    for link in @links
      out.team_merkle[@id] =
        seqno: link.for_client.seqno
        link_id: link.link_id
      out.team_merkle["#{@id}-seqno:#{link.for_client.seqno}"] =
        seqno: link.for_client.seqno
        link_id: link.link_id

    cb null

  #-------------------

  forge_link : ({link_desc, user}, cb) ->
    switch link_desc.type
      when 'root'              then @_forge_link_root              {link_desc, user}, cb
      when 'change_membership' then @_forge_link_change_membership {link_desc, user}, cb
      when 'invite'            then @_forge_link_invite            {link_desc, user}, cb
      when 'leave'             then @_forge_link_leave             {link_desc, user}, cb
      when 'rotate_key'        then @_forge_link_rotate_key        {link_desc, user}, cb
      when 'new_subteam'       then @_forge_link_new_subteam       {link_desc, user}, cb
      else cb (new Error "unhandled link type: #{link_desc.type}"), null

  #-------------------

  _forge_link_helper : ({link_desc, user, proof_klass, sig_arg_team, sig_arg_kms}, cb) ->
    esc = make_esc cb, "_forge_link_helper"
    km_sig = user.keys.default.signing
    seqno = link_desc.seqno or @_next_seqno()
    # the hash_meta last seen by the client who signed this link
    hash_meta = @forge._hash_meta 1000 * seqno
    prev = null
    if @links.length > 0
      prev = @links[@links.length-1].link_id
    if link_desc.corruptors?.prev?
      prev = link_desc.corruptors?.prev prev
    sig_arg =
      seqno: seqno
      user:
        local :
          username : user.username
          uid : user.uid
      merkle_root:
        ctime: 1500570000 + 1
        hash: "ff".repeat 64
        hash_meta: hash_meta
        seqno: 8001
      sig_eng: km_sig.make_sig_eng()
    if prev isnt null
      sig_arg.prev = prev
    if sig_arg_team?
      sig_arg.team = sig_arg_team
    if link_desc.admin?
      sig_arg.team.admin = link_desc.admin
    if sig_arg_kms?
      sig_arg.kms = sig_arg_kms
    if link_desc.corruptors?.sig_arg?
      sig_arg = link_desc.corruptors?.sig_arg sig_arg

    proof = new proof_klass sig_arg
    if link_desc.corruptors?.per_team_key?
      # interpose into the generating of the proof to mess with the per_team_key.
      b4 = proof.set_new_key_section.bind(proof)
      proof.set_new_key_section = (section) ->
        b4 section
        @per_team_key = link_desc.corruptors?.per_team_key section

    # _v_customize_json is a hook in keybase-proofs that is already used inside keybase-proofs
    # piggy back on the hook by adding our own after
    saved_customize_hook = proof._v_customize_json.bind(proof)
    proof._v_customize_json = (payload) =>
      saved_customize_hook payload

      if link_desc.corruptors?.force_inner_key?
        fik = link_desc.corruptors?.force_inner_key
        fik_user = @forge.users[fik.user]
        assert fik_user?, "fik user"
        payload.body.key.username = fik_user.username
        payload.body.key.uid = fik_user.uid
        fik_key = fik_user.keys[fik.key or "default"]
        assert fik_key?, "receiver_user"
        payload.body.key.kid = fik_key.signing.get_ekid().toString "hex"

      link_desc.corruptors?.payload? payload

    await proof.generate_v2 esc defer proof_gen_out
    link_id = SHA256 proof_gen_out.outer, 'hex'

    link_entry = 
      proof: proof
      proof_gen_out: proof_gen_out
      link_id: link_id
      for_client:
        seqno: seqno
        sig: proof_gen_out.armored
        payload_json: proof_gen_out.inner.str
        # uid: proof_gen_out.inner.obj.body.key.uid
        uid: user.uid
        version: 2
        debug_payload: proof_gen_out.inner.obj
        debug_link_id: link_id

    if link_desc.mangle_payload
      link_entry.for_client.payload_json = "%%%%mangled-json%%%%%"

    @links.push link_entry

    # the hashmetas at which this link is the tail of this team's sigchain
    for hm_num in (link_desc.merkle_hashmetas or [])
      @forge.out.merkle_triples["#{@id}-#{@forge._hash_meta hm_num}"] =
        seqno: seqno
        id: link_entry.link_id

    # the user sigchain state at this point in the team chain
    @forge.out.merkle_triples["#{user.uid}-#{hash_meta}"] =
      seqno: 1 # user seqno
      id: user.link_map[1] # link_id

    cb null, {link_entry}

  #-------------------

  _forge_link_root : ({link_desc, user}, cb) ->
    esc = make_esc cb, "_forge_link_root"
    proof_klass = proofs.team.Root
    sig_arg_team =
      id : @id
      name : @name
      members: @_process_members_section link_desc.members

    if link_desc.use_other_key
      await @_new_team_key { link_desc, user, but_dont_save: true }, esc defer {sig_arg_kms}
      await @_new_team_key { link_desc, user }, esc defer {}
    else
      await @_new_team_key { link_desc, user }, esc defer {sig_arg_kms}

    unless link_desc.but_dont_make_a_link
      await @_forge_link_helper {link_desc, user, proof_klass, sig_arg_team, sig_arg_kms}, esc defer()

    cb null

  #-------------------

  # generate a new per-team key and store it on the team
  # unless but_dont_save in which case no state is saved
  _new_team_key: ({link_desc, user, but_dont_save}, cb) ->
    esc = make_esc cb, "_new_team_key"

    ptsk_prev = null
    if @ptsks_list.length > 0
      ptsk_prev = @ptsks_list[@ptsks_list.length-1]

    await PerTeamSecretKeys.make { prng: @forge.prng }, esc defer ptsk 
    generation = @ptsks_list.length + 1
    unless but_dont_save
      @ptsks_list.push ptsk

    # Create the team key box
    await user.get_puk_kms esc defer sender_puk_kms
    receiver_user = @forge.users[@forge.default_user_label]
    assert receiver_user?, "receiver_user"
    await receiver_user.get_puk_kms esc defer receiver_puk_kms
    assert receiver_puk_kms?, "receiver_puk_kms"

    d = {}
    d[user.uid] = new PerTeamKeyBox { uid: user.uid, version : 1, per_user_key_seqno : 1, km: receiver_puk_kms.encryption }
    boxes = new PerTeamKeyBoxes d
    sks = new PerTeamSecretKeySet { generation : generation, boxes, encrypting_km: sender_puk_kms.encryption, prng: @forge.prng }
    await sks.encrypt { ptsk_new : ptsk, ptsk_prev }, esc defer sks_post

    seqno = link_desc.seqno or @_next_seqno()

    sig_arg_kms =
      generation: generation
      signing : ptsk.kms.signing
      encryption : ptsk.kms.encryption

    # early out
    if but_dont_save
      return cb null, {generation, sig_arg_kms}

    # save the key, box, and prevs

    ctext = sks.boxes.d[user.uid].box

    if link_desc.corrupt_box
      ctext[5] = 'f'
      ctext[6] = 'f'
      # guarantee a change
      if ctext[7] is 'f'
        ctext[7] = 'e'
      else
        ctext[7] = 'f'

    entry =
      seqno: seqno
      box:
        nonce: sks.nonce.at(1).buffer().toString 'base64'
        sender_kid: sender_puk_kms.encryption.get_ekid().toString 'hex'
        generation: sks_post.generation
        ctext: ctext.toString 'base64'
        per_user_key_seqno: 1
      prev: sks_post.prev or null

    if link_desc.corrupt_prev
      # guarantee a change
      if entry.prev.slice(0,4) is "ffff"
        entry.prev = 'fffe' + entry.prev.slice(4)
      else
        entry.prev = 'ffff' + entry.prev.slice(4)

    @team_key_boxes.push entry

    cb null, {generation, sig_arg_kms}

  #-------------------

  _forge_link_change_membership : ({link_desc, user}, cb) ->
    esc = make_esc cb, "_forge_link_change_membership"
    proof_klass = proofs.team.ChangeMembership
    sig_arg_team =
      id : @id
      members: @_process_members_section link_desc.members
    await @_forge_link_helper {link_desc, user, proof_klass, sig_arg_team}, esc defer()
    cb null

  #-------------------

  _forge_link_invite : ({link_desc, user}, cb) ->
    esc = make_esc cb, "_forge_link_invite"
    sig_arg_team =
      id : @id
      invites: link_desc.invites
    proof_klass = proofs.team.Invite
    await @_forge_link_helper {link_desc, user, proof_klass, sig_arg_team}, esc defer()
    cb null

  #-------------------

  _forge_link_leave : ({link_desc, user}, cb) ->
    esc = make_esc cb, "_forge_link_leave"
    sig_arg_team =
      id : @id
    proof_klass = proofs.team.Leave
    await @_forge_link_helper {link_desc, user, proof_klass, sig_arg_team}, esc defer()
    cb null

  #-------------------

  _forge_link_rotate_key : ({link_desc, user}, cb) ->
    esc = make_esc cb, "_forge_link_rotate_key"
    sig_arg_team =
      id : @id
    proof_klass = proofs.team.RotateKey

    if link_desc.use_other_key
      await @_new_team_key { link_desc, user, but_dont_save: true }, esc defer {sig_arg_kms}
      await @_new_team_key { link_desc, user }, esc defer {}
    else
      await @_new_team_key { link_desc, user }, esc defer {sig_arg_kms}

    unless link_desc.but_dont_make_a_link
      await @_forge_link_helper {link_desc, user, proof_klass, sig_arg_team, sig_arg_kms}, esc defer()

    cb null

  #-------------------

  _forge_link_new_subteam : ({link_desc, user}, cb) ->
    esc = make_esc cb, "_forge_link_new_subteam"
    sig_arg_team =
      id : @id
      subteam: link_desc.subteam
    proof_klass = proofs.team.NewSubteam
    await @_forge_link_helper {link_desc, user, proof_klass, sig_arg_team}, esc defer()
    cb null

  #-------------------

  # convert a role-set of user labels into a role-set of uvs.
  _process_members_section : (members_desc) ->
    ret = {}
    valid = {"owner": true, "admin": true, "writer": true, "reader": true, "none": true}
    for k of members_desc
      assert valid[k], "invalid members key #{k}"
      ret[k] = @_user_label_list_to_uvs members_desc[k]
    ret

  #-------------------

  _user_label_list_to_uvs : (user_labels) ->
    ret = []
    for user_label in user_labels
      user = @forge.users[user_label]
      unless user? then throw new Error("couldn't find user #{user_label}")
      ret.push user.uv_str()
    ret

  #-------------------

  _hash_team_id : (team_name) ->
    h = SHA256(team_name.toLowerCase())[0...15]
    id = h.toString('hex') + "24"
    return id
  
  #-------------------

  _next_seqno : ->
    if @links.length > 0
      @links[@links.length-1].for_client.seqno + 1
    else
      1


#===================================================

SHA256 = (x, enc) -> createHash('SHA256').update(x).digest(enc)
