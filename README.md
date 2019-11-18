Taproot test vectors
====================

This branch is a fork of the WIP Taproot branch maintained by Pieter Wuille at:

https://github.com/sipa/bitcoin/tree/taproot

Modifications are made to the Taproot functional test:

https://github.com/sipa/bitcoin/blob/taproot/test/functional/feature_taproot.py

This test generates a few hundred random valid (and invalid) Taproot transactions,
covering the in-development specifications of the following BIPs:

- https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

- https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki

- https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki

**NOTE:** At this time,
[changes have been proposed](https://github.com/bitcoin/bips/pull/893)
to the Schnorr signature specification, but those changes have not yet been
approved or merged into the reference implementation this testing branch
is based on.

The test is executed entirely in memory and new transactions are generated
randomly on each run. In order to test alternative implementations of the new
Taproot spec (in my case, for [bcoin](https://github.com/pinheadmz/bcoin/tree/taproot1))
importable test-vectors are especially useful.

In this branch, a JSON file is exported from the `feature_taproot.py` test:

https://github.com/pinheadmz/bitcoin/blob/taproottest1/taproot_tx_data_single_input.json

This file can be used by other developers interested in programming Taproot
transactions. At the top level, the JSON object has two sub-objects: `UTXOs` and
`tests`. The `UTXOs` object itself contains many sub-objects, keyed by a serialized
`COutPoint`, with `value` and `scriptPubKey` as values. These are the coins spent
by the transactions in `tests`. The `tests` object contains several properties
a developer might test for (for example, correctly identifying the annex from a
witness or -- more critically -- executing the complex new
[sigHash algorithm](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#common-signature-message)).

Examples of the layout is as follows:

```
{
  "UTXOs": {
    "bdd5226970c6078b7f0ad9935ca4beebba8c79854a93e2ffbbcf4e749b2b736e04000000": {
      "value": 341801981,
      "scriptPubKey": "512001469a59baff4739c7cf17ab5e2b1129b3eb017e34549cd23770a138b999f067"
    },
    ...
  },
  "tests": [
    {
      "fail_input": 0,
      "standard": false,
      "inputs": [
        {
          "comment": "sighash/p2pk#s0",
          "annex": null,
          "sighash": "f60a9d8509e2e3cb548482438bc389c30e53a206dcc08c099948d3bf24406cf7",
          "script": "04ffffffff204b3361de99428a88ddcde9d5790fa56077d42212eeedaa3386152fa19cedc313ba04feffffff87"
        }
      ],
      "tx": "010000000001013770014cf7e4e7998553faad62cd0928733781f16e004ae30d03e18b5c822970030000000057b986d50454816614000000001976a914a7cf74b43b40d92425e5f09c1a91336434c0ebbd88ac580200000000000017a914a83788cdcfa35959ee6475b30f311d7261d9153787580200000000000017a914a83788cdcfa35959ee6475b30f311d7261d915378758020000000000001976a914f50e9a0e0cb7a996c7830d7cbb1ef4f11e723ade88ac03413a0deee4513f52dc52579d7ba8009b9e32332c1b78b3c5b5679edc486b22cde67ed89df3a4eb63083683678950f410dfae2579ccdc67045b42ce310b88786aa8832d04ffffffff204b3361de99428a88ddcde9d5790fa56077d42212eeedaa3386152fa19cedc313ba04feffffff8721c067fe9c0ca22f9379604fa085b0d987e172290f530b0c6faa9caa9fcc25e25bf277c66c48"
    },
    ...
  ]
}
```

### Notes

- The included JSON file only saved the single-input tests, but the functional test
also generated multi-input transactions. You can generate your own test vectors by
uncommenting the lines at the end of `feature_taproot.py`

- None of these tests execute a multisig with `OP_CHECKSIGADD`. This makes things
much simpler (one signature & sighash per test)

- Everything is a work-in-progress until code is merged into Bitcoin Core. The
BIPs themselves are still being updated.

Enjoy!
