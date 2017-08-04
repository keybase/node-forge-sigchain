# Deterministic and not-secure PRNG

{createHash} = require 'crypto'

sha512 = (x) ->
  h = createHash 'sha512'
  h.update x
  h.digest()

exports.make_prng = ->
  # use chained sha512 as the stream
  state = sha512 "start"
  pool = state

  next = (n_bytes) ->
    # get the next n_bytes from the stream
    out = Buffer.from ''
    while out.length < n_bytes
      more = n_bytes - out.length
      if pool.length == 0
        state = sha512 state
        pool = state
      split = Math.min(more, pool.length)
      out = Buffer.concat [out, pool.slice(0, split)]
      pool = pool.slice(split)

    out

  prng = (n_bytes, cb) ->
    if cb?
      cb next n_bytes
    else
      next n_bytes
  prng.reset = ->
    state = 0
  prng
