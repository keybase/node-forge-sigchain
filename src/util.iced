
exports.copy_obj = copy_obj = (o) ->
  if not o? or (typeof o isnt 'object') then o
  else if Array.isArray o then (copy_obj(e) for e in o)
  else if Buffer.isBuffer o then Buffer.concat [o]
  else
    tmp = {}
    for k,v of o
      tmp[k] = copy_obj v
    tmp
