
minimist = require 'minimist'
CSON = require 'CSON'
fs = require 'fs'
{make_esc} = require 'iced-error'
JSON5 = require 'json5'
{drain} = require 'iced-utils'

#===================================================

class Chain

  #------------------------

  constructor : ({@file, @fh, @format, @outfh}) ->
    @_raw = null
    @_dat = null

  #------------------------

  load : ({}, cb) ->
    esc = make_esc cb, "load"
    await @_read esc defer @_raw
    await @_parse @_raw, esc defer @_dat
    cb null, @_dat

  #------------------------

  get_data : () -> @_dat

  #------------------------

  _read : (cb) -> 
    esc = make_esc cb, "_read"
    if @fh?
      await drain.drain @fh, esc defer dat
    else
      await fs.readFile @file, esc defer dat
      @_guess_format @file
    cb null, dat

  #------------------------

  _guess_format : () ->
    if (m = @file.match /^(.*)\.([^.]*)$/) 
      @stem = m[1]
      @format = m[2] unless @format

  #------------------------

  _parse : (raw, cb) ->
    err = obj = null
    try
      switch (f = @format.toLowerCase())
        when 'json'
          obj = JSON.parse raw
        when 'cson'
          obj = CSON.parse raw
        when 'json5'
          obj = JSON5.parse raw
        else
          err = new Error "unknown format: #{f}"
    catch e
      err = e
    cb err, obj

  #------------------------

  output : (dat, cb) -> 
    if @outfh
      @outfh.write dat
    else if @stem?
      await fs.writeFile "#{@stem}.chain", dat, defer err
    else
      err = new Error 'no output possible'
    cb err

#===================================================

class Forger 

  constructor : ({@chain}) ->

  run : (cb) ->
    ## stubbed out for now, just parrot what we got in
    await @chain.output JSON.stringify(@chain.get_data()), defer err
    cb err

#===================================================

class Runner

  constructor : ({}) ->
    @_files = []

  parse_argv : ({argv}, cb) ->
    parsed = minimist argv
    @_files = parsed._
    @format = parsed.f or parsed.formated
    cb null

  run : ({argv}, cb) ->
    esc = make_esc cb, "run"
    await @parse_argv {argv}, esc defer()

    if @_files.length
      @_chains = (new Chain { file : f, @format } for f in @_files)
    else
      @_chains = [ new Chain { fh : process.stdin, @format, outfh : process.stdout } ]

    for c in @_chains
      await c.load {}, esc defer()
      f = new Forger { chain : c }
      await f.run esc defer()

    cb null

#===================================================

r = new Runner {}
await r.run { argv : process.argv[2...] }, defer err
if err?
  console.log err.toString()
  process.exit 2
