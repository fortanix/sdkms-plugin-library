## Introduction
The plugin derives a child key in a given path from a master key, and signs
a transaction hash. The child key is transient,
This version of the plugin requires an HMAC security object to be created in SDKMS.

## Use cases

The plugin can be used to sign a transaction for UTXO and Ethereum.

## Setup

Create a HMAC type security object.

## Input/Output JSON object format for signing

### Input
For UTXO coin (BTC, LTC, BCH, etc.):

 "hmac_seed_id": "722adb21-107c-4fdf-b28e-2627437815af",
 "coin": "utxo",
 "path": "m/2",
 "msg_hash": "45a0ee821b05400f513891bbb567a99139f3df72e9e1d4b48186841cc5996d2f"


For ETH:

 "hmac_seed_id": "722adb21-107c-4fdf-b28e-2627437815af",
 "coin": "eth",
 "path": "m/0'/42",
 "msg_hash": "45a0ee821b05400f513891bbb567a99139f3df72e9e1d4b48186841cc5996d2f"


### Output

 "coin": "eth",
 "xpub": "<HD-Wallet-Public-Key>",
 "signature": "<ECDSA signature>"


* `path`:           Path of key to be derived for signature, e.g: m/2/10H
* `msg_hash`:       32-byte SHA-3 message hash
* `coin`:           coin type utxo or eth
* `xpub`:           BIP0032 public key
* `signature`:      ECDSA signature

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
 - 2.0 - Several fixes over 1.3:
         - Using Native BIP32 supported by SDKMS
         - Removed unused functions and wrong documentation