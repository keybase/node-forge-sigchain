
{Runner} = require '../../lib/main'
glob = require 'glob'
path = require 'path'

exports.run_cson_examples = (T,cb) ->
  run_examples T, "cson", false, cb

exports.run_iced_examples = (T,cb) ->
  run_examples T, "iced", false, cb

run_examples = (T,stem,team, cb) ->
  expath = [ __dirname, "..", "..", "examples" ]
  if team
    expath.push "teamchains"
  expath.push "*.#{stem}"
  await glob path.join(expath...), T.esc(defer(files), cb)
  for f in files
    r = new Runner {}
    T.waypoint "+ running #{f}"
    argv = [ "-c", f ]
    if team then argv.push "-t"
    await r.run { argv }, T.esc(defer(), cb)
    T.waypoint "- ran #{f}"
  cb null

exports.run_team_examples = (T,cb) ->
  run_examples T, "iced", true, cb

