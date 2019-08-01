description: "Simplest test"

users: {
  "herb": {}
}

teams: {
  cabal : {
    links : [
      { type: "root", members: { owner: ["herb"] } },
      { type : "rotate_key" },
      { type : "rotate_key_hidden" },
      { type : "rotate_key" }
      { type : "rotate_key_hidden" },
    ]
  }
}

sessions: [
  loads : [{ error : false }]
]
