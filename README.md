Taproot Test Vectors
====================

This branch is forked from Bitcoin Core tagged release v0.21.1 at commit 194b9b8792d9b0798fdb570b79fa51f1d1f5ebaf

The test [test/functional/feature_taproot.py](test/functional/feature_taproot.py)
was modified to dump all test vectors into a single file, which has been committed
to the root of this branch [taproot_test_vectors.json](taproot_test_vectors.json).

Note that the Taproot test already accepts an extra argument `--dumptests`, but
that feature produces multiple files per transaction in a more complicated format
and also does not include deeper test vectors like `sighash` and `annex`.

The file `taproot_test_vectors.json` is structured as follows:

### File
```
[
  <Transaction>
  ...
]
```

An array of transaction objects.


### Transaction
```
{
  tx: <stripped transaction>
  inputs: [<Input> ...]
  prevouts: [<Prevout> ...]
}
```

`<stripped transaction>`: The transaction without any scriptSig, witness,
or segwit flag/marker bytes, serialized as a hex-encoded string.

`<inputs>`: An array of input data objects (defined below) in order of the corresponding inputs
of the transaction.

`<prevouts>`: An array of prevout data (defined below) in order of the corresponding inputs
of the transaction.

### Input
```
{
  fail: {
    scriptSig: <hex-encoded input script or empty "">,
    witness: [
      <hex-encoded witness stack item>
      ...
    ],
    annex: <hex-encoded annex blob from witness stack or empty "">,
    sighash: <hex-encoded signature hash signed by this input or empty "">
  },
  success: {
    scriptSig: <hex-encoded input script or empty "">,
    witness: [
      <hex-encoded witness stack item>
      ...
    ],
    annex: <hex-encoded annex blob from witness stack or empty "">,
    sighash: <hex-encoded signature hash signed by this input or empty "">
  },
  comment: "a compact description of the spend type",
  standard: <bool>
}
```

Each input has a `success` and `fail` object. In some cases one of these may be `null`.
Each object includes an output script and witness stack. Each object also includes
additional strings `annex` and `scriptSig` which can be used to test individual methods
of an overall taproot implementation. The `comment` string comes from the taproot
test and helps identify the type of spend / test coverage and the `standard` flag
indicates whether or not the `success` input is passes standard relay policy checks.

### Prevout
A hex-encoded serialization with the following data:
- value (uint32)
- output script (aka witness program)

Example:
```
98dd0e0000000000225120a1218296a112159c932f393e8dd48c11735e6ec934b27a0c8565b3e12ada6ac4
```

This string encodes a value of 974,232 satoshis (`98dd0e0000000000` little-endian)
with output script `225120a1218296a112159c932f393e8dd48c11735e6ec934b27a0c8565b3e12ada6ac4`.
That script encodes a 32 (`0x22`) byte witness program version 1 (`0x51`) with 32 (`0x20`)
byte public key `a1218296a112159c932f393e8dd48c11735e6ec934b27a0c8565b3e12ada6ac4`.

### Complete example

The following json blob is an example of the test vector file if it only had one transaction.
Note these details about the transaction:

- It has 2 inputs.
- When both inputs are filled with the "success" data, the TX will pass standardness checks.
- When input 0 is filled with "failure" data, that input will be invalid due to
an unknown sighash type.
- When input 1 is filled with "failure" data, that input will be invalid due to a
`false` stack execution (input signed with the wrong private key).
- Input 0 is a taproot spend using script path, with no annex.
- Input 1 is a witness v0 script hash spend with a single public key and OP_CHECKSIG 


```
[
  {
    "tx": "e0fe7e0502f5a157bd27fceb03b34d8084c475a8941ed4717a70eafaf747c180663ca86890de0100000065239cad64aced0655040ec58ffbf83ceffa5f8816882debdf6a1916eca943a59e5fcfbee5010000000366f7ab04cd067900000000001976a914a490410c3af7fb9b4ebb942e28d2e2ac0d0b497e88ac580200000000000017a9146b8dfcadc8fdd2b97a56cebda579c35fffd8595d87580200000000000017a9140b3800d72caaade7dfa8aa508985e32cf609f2198758020000000000001976a914c45021cf20ec0a54d83f70f0f3a3a21862bfc35a88ac62000000",
    "inputs":
    [
      {
        "fail":
        {
          "scriptSig": "",
          "witness":
          [
            "17fa14cbc27554ad806074b35aa4e60707587822f5be9a370a141f8bc98b7317b41f7fa47d99a9979973cab8f58a9da76d148ad47f35ee7dda0e7c246cb0637612",
            "205ab878e032b86f61d7cc1fbf33cd42116c02ef1cc53a58ade82bc16e7b3154e5ad51ab",
            "c07ca277754ed08bfb1370beec7a1976964374439bd9db655fcb64c80e150cd337c108f31ee44bc3793484ac2c31d0c119d9fcfff6c70d1bd0252d30ee8a1a7e8406adf54f15710baa856a61ee804b7fcf37be38f5a64722a01eabc2eb0dc60e83"
          ],
          "annex": null,
          "sighash": "0244f8f9f9c5374d02607d2b75ca101fd189cbd9477414b422509dd44ce3444e"
        },
        "success":
        {
          "scriptSig": "",
          "witness":
          [
            "5d828c481b400273ecd423eb1823d47b38a714cf44385082d8a58c66e85eb72d860a5a0692ec877f709b8ad368150b2c9d156489c1f08c81e445df08e7fb0a0c83",
            "205ab878e032b86f61d7cc1fbf33cd42116c02ef1cc53a58ade82bc16e7b3154e5ad51ab",
            "c07ca277754ed08bfb1370beec7a1976964374439bd9db655fcb64c80e150cd337c108f31ee44bc3793484ac2c31d0c119d9fcfff6c70d1bd0252d30ee8a1a7e8406adf54f15710baa856a61ee804b7fcf37be38f5a64722a01eabc2eb0dc60e83"
          ],
          "annex": null,
          "sighash": "51613fbbd48567f9c38fc899bc9d0d1f354ac215ec74dfb7246be3df7b64beed"
        },
        "comment": "sighash/scriptpath_unk_hashtype_12",
        "standard": true
      },
      {
        "fail":
        {
          "scriptSig": "",
          "witness":
          [
            "30440220572703d5ef5f2159e4fef760dd8d0c944c9ff6210e78619191b9bd3251b3378002204f20013f71fec7d0b19fe1c533307ada82e590df72acfbd026a84ec73a6fe86c83",
            "2102b84525574042c8ba2ea2eaa8654e21dd881a7dc0d8e75d1732ef670959858e25ac"
          ],
          "annex": null,
          "sighash": "16012fa9da5a28f110f2819e3df1528ff6913f4a6230a2a8d95253c58dce5547"
        },
        "success":
        {
          "scriptSig": "",
          "witness":
          [
            "3044022015a21baf11988ef33cdafd5a128774c98d5f15d0669c719017f59ad142a7235f02205f75b9f609691f57c57e66c39cbdbffe321ca226c6017d4e9ffd86c3c77a545f83",
            "2102b84525574042c8ba2ea2eaa8654e21dd881a7dc0d8e75d1732ef670959858e25ac"
          ],
          "annex": null,
          "sighash": "16012fa9da5a28f110f2819e3df1528ff6913f4a6230a2a8d95253c58dce5547"
        },
        "comment": "legacy/pk-wrongkey",
        "standard": true
      }
    ],
    "prevouts":
    [
      "a6fa0e0000000000225120899202eb8cb4c859996a62001ffb9971df078b67b1f0110394504c51c527dd03",
      "44de6b00000000002200208e8fc38a65e7ec9b21ad01d3f1f6bbc573ff3c1d784e0afa609549226e3442ed"
    ]
  }
]
```



