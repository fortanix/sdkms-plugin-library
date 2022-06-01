## Ethereum Signer

Version: 1.0

## Short Description


This plugin implements an Ethereum Signer. Each Ethereum Signer is paired with a `MASTER_KEY`. Several wallets can be added to each Ethereum Signer. Several keys can be added to each wallet.

A wallet can optionally be registered to support 2FA using Time-based One-Time Passwords (TOTP). 

To support TOTP, this plugin implements the algorithms described in RFC 6238 (TOTP). The code is adapted from https://github.com/remjey/luaotp/blob/v0.1-6/src/otp.lua

Customers of B2C crypto-currency wallet providers can register with the secure 2FA service provided via this plugin. This provides them with additional security. Specifically, a customers assets cannot be spent without their explicit involvement in the transaction.  


## Use cases

The plugin can be used to:

 - Optionally Register a user for 2FA using TOTP
 - Derive public key
 - Sign data or Ethereum transaction

## Setup

 - Generate master key manually

 - **Example Master Key:** `xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U`

 - Import master key in SDKMS as secret raw key and name it as `MASTER_KEY`.

## Register a user for 2FA using TOTP

 **Input Format**

```
{
  "operation": "register",
  "walletName": "string, e.g., alice@acme.com"
}
```

**Output Format**

```
{
  "url": "otpauth url",
  "security_object": "security object"
}
```

**Example Input**

```
{
  "operation": "register",
  "walletName": "alice@acme.com"
}
```

**Example Output**

```
{
  "url": "otpauth://totp/Fortanix%20DSM:alice%40acme.com?secret=4RWQ3LFNQEWIBZZYGIYYXAU7&issuer=Fortanix%20DSM&period=30&digits=6&algorithm=SHA1",
  "security_object": "totp/alice@acme.com"
}
```


## Derive public key

 **Input Format**

```
{
  "operation": "getPubKey",
  "walletName": "string",
  "keyIndex": "number as string"
}
```


**Output Format**

```
{
  "xpub": "public key"
}
```

**Example Input**

```
{
  "operation": "getPubKey",
  "walletName": "alice@example.com",
  "keyIndex": "0"
}
```

 **Example Output**

```
{
  "xpub": "02c04c4e03921809fcbef9a26da2d62b19b2b4eb383b3e6cfaaef6370e75144774"
}
```

## Sign data or Ethereum transaction

 **Input Format**

```
{
  "operation": "sign",
  "walletName": "string",
  "keyIndex": "number as string",
  "msgHash": "<32-Byte-Message-Hash>"
  "code": "number as string" // code to be provided only if wallet is registered for 2FA.
}
```


**Output Format**

```
{
  "r": "r-value of signature",
  "s": "s-value of signature",
  "xpub": "public key"
}
```


**Example Input**

```
{
  "operation": "sign",
  "walletName": "alice@acme.com",
  "keyIndex": "0",
  "msgHash": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
  "code": "583824"  // code to be provided only if wallet is registered for 2FA.
}
```

**Example Output**

```
{
  "xpub": "036b3c4b464c34d0478341a43f1af9fa93234e99acc175494e94321af4527ef14c",
  "s": "060647fae5f8a755fc7d6adb3b87bfb025fbdd0b777001d69a32de0c6cabc414",
  "r": "a5f4c06a3fffca8cdf44b34451bc87e36d9ff23cc9c1e26c7e2e9165b35b55be"
}
```


## Security Considerations

The plugin stores one `HMAC` key per 2FA account, this key is not exportable so that the secret can only be accessed when the account is created (through the `register` operation). However, note that TOTP is a shared secret scheme where the `HMAC` secret is known to both the prover and verifier parties. The verifier (in this case the plugin) is executed inside Fortanix DSM and is protected with strong security mechanisms available in DSM. The prover, i.e. the 2FA app, and any other tools with access to the URL or QR code on the other hand are not protected in the same way. Care should be taken to avoid compromising the secret through such tools.

The plugin additionally stores some metadata with the `HMAC` key to keep track of the TOTP parameters as well as the last counter value (last timestamp divided by period). The counter is updated every time the plugin is invoked to verify a code. Any user or application with access to the `HMAC` key can therefore find out the timestamp of the last successful verification performed by the plugin for that account. Therefore it is recommended to limit access to the `HMAC` key(s) used by this plugin as much as possible.