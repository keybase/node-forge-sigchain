
{make_esc} = require 'iced-error'
{akatch,unix_time} = require('iced-utils').util
kbpgp = require 'kbpgp'

#===================================================

exports.Forge = class Forge

  #-------------------

  constructor : ({@chain}) ->
    @_keyring = {}
    @_links = []
    @_assertions = []
    @_time = 0
    @_start = null
    @_now = null
    @_expires = 0
    @_seqno = 1
    @_prev = null    

  #-------------------

  _compute_now : () ->
    @_now = unix_time() unless @_now?
    @_now

  #-------------------

  _make_key : ({km, obj}) -> 
    k = new Key { km, ctime : @_compute_now(), expires : (obj.expires or @_expires) }
    @_keyring[k.get_ekid().toString('hex')] = k
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
      @_start = if (t = @chain.time)? then @_compute_time(t) else @_compute_now()
      @_expires = @chain.expires or 60*60*24*364*10
      @_user = @chain.user or "tester_ralph"
    catch e
      err = e
    cb err

  #-------------------

  _forge_link : ({link}, cb) ->
    switch link.type
      when 'eldest' then @_forge_eldest_link {link}, cb
      when 'subkey' then @_forge_subkey_link {link}, cb
      when 'sibkey' then @_forge_sibkey_link {link}, cb
      when 'revoke' then @_forge_revoke_link {link}, cb
      else cb (new Error "unhandled link type: #{link.type}"), null

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
          await kbpgp.generate_rsa { userid : @_user }, esc defer km
        when 'pgp_ecc'
          await kbpgp.generate_ecc { userid : @_user }, esc defer km
        else
          err = new Error "unknown key type: #{typ}"
    else if required then err = new Error "Required to generate key but none found"
    key = if km? and not err? then @_make_key{km, obj} else null
    cb err, key

  #-------------------

  _forge_eldest_link : ({link}, cb) -> 
    esc = make_esc cb, "_forge_eldest_link"
    await @_gen_key { obj : link, required : true }, esc defer km
    cb null

  #-------------------

  forge : (cb) ->
    esc = make_esc cb, "Forge::forge"
    await @_init esc defer()
    for link in @chain.links
      await @_forge_link { links }, esc defer out
      @_links.push out

    ## stubbed out for now, just parrot what we got in
    await @chain.output JSON.stringify(@chain.get_data()), defer err
    cb err

#===================================================

