
{Runner} = require '../../lib/main'
glob = require 'glob'
path = require 'path'

exports.run_cson_examples = (T,cb) ->
  run_examples T, "cson", cb

exports.run_iced_examples = (T,cb) ->
  run_examples T, "iced", cb

run_examples = (T,stem,cb) ->
  await glob path.join(__dirname, "..", "..", "examples", "*.#{stem}"), T.esc(defer(files), cb)
  for f in files
    r = new Runner {}
    T.waypoint "+ running #{f}"
    await r.run { argv : [ "-c", f ] }, T.esc(defer(), cb)
    T.waypoint "- ran #{f}"
  cb null
