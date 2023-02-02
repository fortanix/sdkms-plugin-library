## Introduction
The plugin derives a child key in a given path from a master key, and signs
a transaction hash. The child key is transient; it only exists during the
plugin execution. This version of the plugin requires the master key to be
exportable. In upcoming version 2.0, this condition is removed for better
security.

## Use cases

The plugin can be used to sign a transaction for UTXO and Ethereum.

## Setup

Import the BIP32 master key as a BIP32 object - text import.
**Example Master Key:**
`xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U`

## Input/Output JSON object format for signing

### Input
For UTXO coin (BTC, LTC, BCH, etc.):

 "master_key_id": "5aef3e3f-7927-49b2-b252-bf84b6980f95",
 "coin": "utxo",
 "path": "m/2",
 "msg_hash": "45a0ee821b05400f513891bbb567a99139f3df72e9e1d4b48186841cc5996d2f"


For ETH:

 "master_key_id": "5aef3e3f-7927-49b2-b252-bf84b6980f95",
 "coin": "eth",
 "msg_hash": "45a0ee821b05400f513891bbb567a99139f3df72e9e1d4b48186841cc5996d2f"


### Output

 "coin": "eth",
 "xpub": "<HD-Wallet-Public-Key>",
 "coin_signature": "<Bitcoin-canonicalized-ECDSA-signature>",
 "signature": "<ECDSA signature>"


* `master_key_id`:  UUID of master key imported in DSM
* `path`:           Path of key to be derived for signature, e.g: m/2/10H
* `msg_hash`:       32-byte SHA-3 message hash
* `coin`:           coin type utxo or eth
* `xpub`:           BIP0032 public key
* `signature`:      ECDSA signature
* `coin_signature`: Bitcoin canonicalized ECDSA signature

## References

- https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- https://en.bitcoin.it/wiki/Bech32

### Release Notes
 - Initial release
 - 1.2 - See github.com/fortanix/sdkms-plugin-library/pull/6
 - 1.3 - Code refactor for legibility w.r.t. the BIP0032 specification.
         Several fixes over 1.2:
         - Fix compilation errors, code lint
         - Removed unused functions and wrong documentation
         - Use bytes everywhere
         - Specify that we support private -> private key derivation.
## References

- [bip-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
