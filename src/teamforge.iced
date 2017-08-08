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
      team_merkle: {}
      merkle_triples: {} # map from keys with a dash "LeafID-HashMeta" to MerkleTriple's
      sessions: @chain.sessions
    @_link_id_gen = new LinkIDGen

    # This is the user who is loading teams.
    # They are also the default for forging actions when no one else is specified.
    @default_user_label = "herb"

    for user_label, user_desc of @chain.users
      await User.make {forge:@, label: user_label}, esc defer user
      @users[user_label] = user
      await user.apply @out, esc defer()

      @out.merkle_triples["#{@out.users[user_label].uid}-#{@_hash_meta 1000}"] =
        seqno: 1
        id: @out.users[user_label].link_map[1] # link_id

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

  constructor : ({@forge, @label, @username, @eldest_seqno}) ->
    # pass

  #-------------------

  _init : (cb) ->
    esc = make_esc cb, "TeamForge::User::_init"

    @username or= @label
    @eldest_seqno or= 1
    @uid = @_gen_uid {@label}
    @keys = {} # label -> keypair

    # generate an eldest key
    await @forge._gen_key 'eddsa', esc defer km_sig
    await @forge._gen_key 'dh', esc defer km_enc
    @keys["default"] =
      signing: km_sig
      encryption: km_enc
      pubkeyv2nacl:
        deviceType: "desktop"
        deviceDescription: "home thing"
        deviceID: "fbd762facdfad44709aef63a9a8cdf18"
        base:
          provisioning:
            sigChainLocation:
              seqType: 1
              seqno: 1
            time: 0
            firstAppearedUnverified: 0
            prevMerkleRootSigned:
              hashMeta: @forge._hash_meta 500
              seqno: 0
            signingKID: ""
          eTime: 2005146762000
          cTime: 1500570762000
          isEldest: true
          isSibkey: true
          kid: km_sig.get_ekid().toString "hex"

    @puk_secrets =
      1: @forge.prng(32).toString('hex')
      # 1: "5b7923a534415f19ac4f5c97f32605f1b542bcf5f134b57241dee2b790c09648"

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
      link_map:
        1: @forge._link_id_gen.next_link_id()
      tmp_puk_enc_kid: puk_kms.encryption.get_ekid().toString 'hex'

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
    await PerTeamSecretKeys.make { prng: @forge.prng }, esc defer ptk_secrets 
    @ptsks_list = [ptk_secrets]
    @links = []
    cb null

  #-------------------

  # Impose upon the forge output.
  apply : (out, cb) ->
    esc = make_esc cb, "Team::apply"

    out.teams[@label] =
      id: @id
      links: (link.for_client for link in @links)
      team_key_box: @team_key_box
      tmp_tk_sec: @ptsks_list[0].seed.toString 'hex'
      tmp_tk_sig_kid: @ptsks_list[0].kms.signing.get_ekid().toString 'hex'

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
      else cb (new Error "unhandled link type: #{link_desc.type}"), null

  #-------------------

  _forge_link_root : ({link_desc, user}, cb) ->
    esc = make_esc cb, "_forge_link_root"
    km_sig = user.keys.default.signing
    seqno = link_desc.seqno or (@links.length + 1)
    ptsk = @ptsks_list[0]
    hash_meta = @forge._hash_meta 1000
    sig_arg =
      seqno: seqno
      user:
        local :
          username : user.username
          uid : user.uid
      team:
        id : @id
        name : @name
        members: @_process_members_section link_desc.members
      merkle_root:
        ctime: 1500570000 + 1
        hash: "ff".repeat 64
        hash_meta: hash_meta
        seqno: 8001
      sig_eng: km_sig.make_sig_eng()
      kms:
        generation: 1
        signing : ptsk.kms.signing
        encryption : ptsk.kms.encryption
    if link_desc.corruptors?.sig_arg?
      sig_arg = link_desc.corruptors?.sig_arg sig_arg

    proof = new proofs.team.Root sig_arg
    if link_desc.corruptors?.per_team_key?
      b4 = proof.set_new_key_section.bind(proof)
      proof.set_new_key_section = (section) ->
        b4 section
        @per_team_key = link_desc.corruptors?.per_team_key section
    await proof.generate_v2 esc defer proof_gen_out
    link_id = SHA256 proof_gen_out.outer, 'hex'

    @links.push
      proof: proof
      proof_gen_out: proof_gen_out
      link_id: link_id
      for_client:
        seqno: seqno
        sig: proof_gen_out.armored
        payload_json: proof_gen_out.inner.str
        uid: proof_gen_out.inner.obj.body.key.uid
        version: 2

    # Create the team key box
    await user.get_puk_kms esc defer sender_puk_kms
    receiver_user = @forge.users[@forge.default_user_label]
    assert receiver_user?, "receiver_user"
    await receiver_user.get_puk_kms esc defer receiver_puk_kms
    assert receiver_puk_kms?, "receiver_puk_kms"

    d = {}
    d[user.uid] = new PerTeamKeyBox { uid: user.uid, version : 1, per_user_key_seqno : 1, km: receiver_puk_kms.encryption }
    boxes = new PerTeamKeyBoxes d
    sks = new PerTeamSecretKeySet { generation : 1, boxes, encrypting_km: sender_puk_kms.encryption, prng: @forge.prng }
    await sks.encrypt { ptsk_new : ptsk }, esc defer sks_post

    @team_key_box =
      nonce: sks.nonce.at(1).buffer().toString 'base64'
      sender_kid: sender_puk_kms.encryption.get_ekid().toString 'hex'
      generation: sks_post.generation
      ctext: sks.boxes.d[user.uid].box.toString 'base64'
      per_user_key_seqno: 1

    cb null

  #-------------------

  _forge_link_change_membership : ({link_desc, user}, cb) ->
    esc = make_esc cb, "_forge_link_change_membership"
    km_sig = user.keys.default.signing
    seqno = link_desc.seqno or (@links.length + 1)
    hash_meta = @forge._hash_meta 1000
    prev = @links[@links.length-1].link_id
    if link_desc.corruptors?.prev?
      prev = link_desc.corruptors?.prev prev
    sig_arg =
      seqno: seqno
      user:
        local :
          username : user.username
          uid : user.uid
      team:
        id : @id
        members: @_process_members_section link_desc.members
      merkle_root:
        ctime: 1500570000 + 1
        hash: "ff".repeat 64
        hash_meta: hash_meta
        seqno: 8001
      prev: prev
      sig_eng: km_sig.make_sig_eng()
    if link_desc.corruptors?.sig_arg?
      sig_arg = link_desc.corruptors?.sig_arg sig_arg

    proof = new proofs.team.ChangeMembership sig_arg
    if link_desc.corruptors?.per_team_key?
      b4 = proof.set_new_key_section.bind(proof)
      proof.set_new_key_section = (section) ->
        b4 section
        @per_team_key = link_desc.corruptors?.per_team_key section
    await proof.generate_v2 esc defer proof_gen_out
    link_id = SHA256 proof_gen_out.outer, 'hex'

    @links.push
      proof: proof
      proof_gen_out: proof_gen_out
      link_id: link_id
      for_client:
        seqno: seqno
        sig: proof_gen_out.armored
        payload_json: proof_gen_out.inner.str
        uid: proof_gen_out.inner.obj.body.key.uid
        version: 2

    cb null

  #-------------------

  _forge_link_invite : ({link_desc, user}, cb) ->
    esc = make_esc cb, "_forge_link_invite"
    km_sig = user.keys.default.signing
    seqno = link_desc.seqno or (@links.length + 1)
    hash_meta = @forge._hash_meta 1000
    prev = @links[@links.length-1].link_id
    if link_desc.corruptors?.prev?
      prev = link_desc.corruptors?.prev prev
    sig_arg =
      seqno: seqno
      user:
        local :
          username : user.username
          uid : user.uid
      team:
        id : @id
        invites: link_desc.invites
      merkle_root:
        ctime: 1500570000 + 1
        hash: "ff".repeat 64
        hash_meta: hash_meta
        seqno: 8001
      prev: prev
      sig_eng: km_sig.make_sig_eng()
    if link_desc.corruptors?.sig_arg?
      sig_arg = link_desc.corruptors?.sig_arg sig_arg

    proof = new proofs.team.Invite sig_arg
    if link_desc.corruptors?.per_team_key?
      b4 = proof.set_new_key_section.bind(proof)
      proof.set_new_key_section = (section) ->
        b4 section
        @per_team_key = link_desc.corruptors?.per_team_key section
    await proof.generate_v2 esc defer proof_gen_out
    link_id = SHA256 proof_gen_out.outer, 'hex'

    @links.push
      proof: proof
      proof_gen_out: proof_gen_out
      link_id: link_id
      for_client:
        seqno: seqno
        sig: proof_gen_out.armored
        payload_json: proof_gen_out.inner.str
        uid: proof_gen_out.inner.obj.body.key.uid
        version: 2

    cb null

  #-------------------

  _forge_link_leave : ({link_desc, user}, cb) ->
    esc = make_esc cb, "_forge_link_leave"
    km_sig = user.keys.default.signing
    seqno = link_desc.seqno or (@links.length + 1)
    hash_meta = @forge._hash_meta 1000
    prev = @links[@links.length-1].link_id
    if link_desc.corruptors?.prev?
      prev = link_desc.corruptors?.prev prev
    sig_arg =
      seqno: seqno
      user:
        local :
          username : user.username
          uid : user.uid
      team:
        id : @id
      merkle_root:
        ctime: 1500570000 + 1
        hash: "ff".repeat 64
        hash_meta: hash_meta
        seqno: 8001
      prev: prev
      sig_eng: km_sig.make_sig_eng()
    if link_desc.corruptors?.sig_arg?
      sig_arg = link_desc.corruptors?.sig_arg sig_arg

    proof = new proofs.team.Leave sig_arg
    if link_desc.corruptors?.per_team_key?
      b4 = proof.set_new_key_section.bind(proof)
      proof.set_new_key_section = (section) ->
        b4 section
        @per_team_key = link_desc.corruptors?.per_team_key section
    await proof.generate_v2 esc defer proof_gen_out
    link_id = SHA256 proof_gen_out.outer, 'hex'

    @links.push
      proof: proof
      proof_gen_out: proof_gen_out
      link_id: link_id
      for_client:
        seqno: seqno
        sig: proof_gen_out.armored
        payload_json: proof_gen_out.inner.str
        uid: proof_gen_out.inner.obj.body.key.uid
        version: 2

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
  

#===================================================

SHA256 = (x, enc) -> createHash('SHA256').update(x).digest(enc)
