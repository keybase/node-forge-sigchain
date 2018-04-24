
pgp_utils = require('pgp-utils')
{json_stringify_sorted} = pgp_utils.util
{unpack,pack} = require 'purepack'

chain :
  user : "max32"
  ctime : "now"
  expire : 10000000
  links : [
    {
      type : "eldest"
      label : "e"
      key : gen : "eddsa"
      version : 2
    },
    {
      ctime : "+100"
      label : "monero"
      type : "btc"
      signer : "e"
      version : 2
      ignore_if_unsupported : true
      stubbed : true
      corrupt_v2_proof_hooks :
        pre_generate_outer : ({inner}) ->
          inner.obj.body.type = "monero"
          inner.str = json_stringify_sorted inner.obj
        post_generate_outer : ({outer, res}) ->
          tmp = unpack outer
          tmp[4] = 20
          res.outer = pack tmp
    }
  ]

