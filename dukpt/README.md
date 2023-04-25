# Derived Unique Key Per Transaction (DUKPT)

## Introduction
DUKPT plugin is an DSM implementation of the Derived Unique Key Per
Transaction process that's described in Annex A of ANS X9.24-2009. This module
provides DUKPT decryption using the 3DES scheme. It decrypts the encrypted card
information using the KSN and BDK-ID as inputs to the plugin and generates
decrypted/plain card information.

Initially there is a Base Derivation Key (BDK) that is used to generate the
"Initial PIN Encryption Key" (IPEK). The BDK always stays in the HSM and is
never injected into the devices. It is known only by the manufacturer and the
merchant. The "Key Serial Number" (KSN) and IPEK are injected into each device.
The KSN is sent with the "crypt" material so that the receiving end can also
decrypt it. The last 21 bits of the KSN are a counter that gets incremented
every transaction.

There is a single DUKPT plugin, with three supported operations: `import`,
`encrypt`, and `decrypt`.

## Use Cases
As described above in the Introduction, the value of DUKPT is the ability to
secure many independent messages in such a way that compromising the keys for
any individual message doesn't endanger other messages while still minimizing
the number of keys that need to be stored and managed. The canonical example of
this, and the use case for which this procedure was developed, is to encrypt
payment information during transactions.

## Setup
### Using DSM Plugins
* Plugins are an independent and secure subsystem where business logic can be
  executed inside DSM.
* Plugins are invoked using a REST API similar to the cryptographic and key
  management APIs.
* Plugins are identified by UUID, like apps and security objects.
* To invoke a plugin, make a POST request to `https://<API endpoint>/sys/v1/plugins/<uuid>`.
  The POST request body must be either valid
  JSON or empty. The exact structure is defined by the plugin.
* The request may return:
    - 200 OK with a JSON response body,
    - 204 No Content with empty response body, or
    - a 4xx/5xx error with a plain text error message response body.

### Invoking DSM plugins from DSM Python CLI
Check the DSM CLI README for information on setting up the CLI.

Login to sdkms inorder to invoke plugin:

`$ sdkms-cli user-login`

To invoke a plugin:

`$ sdkms-cli invoke-plugin --name dukpt --in <decrypt-in.json>`

* Plugins can either be invoked using `--name` or `--id`, taking the plugin's
  name or UUID respectively.
* `in` : Path to input json file.

## DUKPT Input/Output JSON Formats
The following sections specify the fields in the inputs and outputs of the
plugin's operations, which are JSON maps.

### DUKPT Import Operation
#### Input
* `operation` : Must be the string `import` for importing BDKs.
* `name` : A string to be used as the name of the key in DSM. Must be unique.
* `material` : A string containing the 16 hex encoded bytes of the key material.

#### Output
* `key_id` : The UUID of the imported key in DSM. Referred to in the other
  operations as `bdk_id`.

### DUKPT Encrypt and Decrypt
#### Input
* `operation` : Either `encrypt` or `decrypt`, for encryption and decryption
  respectively.
* `bdk_id` : The UUID of the imported BDK key to use.
* `ksn` : Key serial number, hex encoded.
* `key_mode` : The method used for deriving the session key from the IPEK.
  Possible values are:
    - `datakey`
    - `pinkey`
    - `mackey`
* `card_data` : The data to be encrypted or decrypted, encoded in a string in
  accordance with the encoding specified below.
* `encoding` : For the `encrypt` operation this is the encoding of the data to
  be encrypted. For `decrypt`, this is the encoding that the data should be
  returned in.
  Possible values are:
    - `base64`
    - `hex`

#### Output
* `card_data` : The result of the encryption or decryption.

## Example Usages
### DUKPT Import
Imports a BDK into DSM for use with the other operations.

#### Example Input
```json
    { "operation": "import",
      "name": "my_bdk",
      "material": "0123456789ABCDEFFEDCBA9876543210" }
```

#### Example Output
```json
    { "key_id": "d17e7c0c-3246-41c4-9824-c98d2c6515fb" }
```

### DUKPT Encrypt and Decrypt
Encrypts or decrypts data with a key derived from the given BDK and KSN.

#### Example Input
Below is a sample input json to the DSM DUKPT plugin's decrypt operation. The
structure is the same for encryption, though the semantics change slightly as
described above.
```json
    { "operation": "decrypt",
      "bdk_id": "fd1fbe76-6d64-4d30-b351-e79449e1eb77",
      "ksn": "FFFF9876543210E00008",
      "key_mode": "datakey",
      "card_data": "y07Fue/gKW7x9yDM06LZBg==",
      "encoding": "base64" }
```

#### Example Output
```json
    { "card_data": "Zm9ydGFuaXg=" }
```

## References

* [NodeJS DUKPT implementation](https://github.com/dpjayasekara/node-dukpt)
* [C# DUKPT implementation](https://github.com/sgbj/Dukpt.NET)
* [Fortanix Self-Defending KMS developers guide plugin](https://support.fortanix.com/sdkms/developers-guide-plugin.html)
* [Fortanix Self-Defending KMS plugins API](https://support.fortanix.com/api/#/Plugins)
