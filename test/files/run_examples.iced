
{Runner} = require '../../lib/main'
glob = require 'glob'
path = require 'path'

exports.run_examples = (T,cb) ->
  await glob path.join(__dirname, "..", "..", "examples", "*.cson"), T.esc(defer(files), cb)
  for f in files
    r = new Runner {}
    T.waypoint "+ running #{f}"
    await r.run { argv : [ "-c", f ] }, T.esc(defer(), cb)
    T.waypoint "- ran #{f}"
  cb null
