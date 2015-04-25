
#===================================================

exports.Forge = class Forge

  constructor : ({@chain}) ->

  forge : (cb) ->
    ## stubbed out for now, just parrot what we got in
    await @chain.output JSON.stringify(@chain.get_data()), defer err
    cb err

#===================================================

