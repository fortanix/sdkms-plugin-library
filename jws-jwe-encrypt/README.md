# JWS+JWE Encrypt

## Introduction
This plugin, performs encrypt using JWE standards:  enc:  A256CBC-HS512 alg:  RSA-OAEP-256.

This plugin performs the following steps:

1. It generates a JWS from the `payload`.
2. Generates a header for JWS containing `alg` and `typ`, as:
  ```
    {typ : "JWT", "alg" : "RS256"}
  ```
3. Encodes header and input payload to the Base64URL format.
4. Constructs the JWS Signing input by concatenating header and payload.
5. Sign the above constructed `Jws Signing input` by RSA private key (provided in input) using SHA-256 and mode as PKCS1-v1_5.
6. Encodes the signature in the Base64URL format and constructs JWS by concatenating header, payload, and signature by using `"."` as a separator. It will use this `jws` as input payload to `JWE`.
7. Generate the header for JWE, containing `alg, enc, typ`.
    ```
        {alg = "RSA-OAEP-256", enc = "A256CBC-HS512", typ = "JWT"}
    ```
8. Generate an exportable `transient` `AES` key of size `256` bits and an exportable `transient` `HMAC` key of size `256` bits.
9. Encrypts the above generated JWS using the transient AES key in `CBC` mode.
10. Generate `aad` using the `header` and `al` to store the size of `aad`.
11. Creates an input payload for HMAC consisting of `aad, iv, cipher, al`.
12. Creates a HMAC of the payload created above using HMAC key using `SHA-512` as the hashing algorithm.
13. Truncate the digest generated above to half the length and use as authentication-tag.
14. Import the `certificate` as a transient key.
15. Encrypt the combined transient AES key and HMAC key with the `certificate` given as input, using `OAEP_MGF1_SHA256` as the mode and `RSA` is the algorithm.
16. Returns the header, encrypted transient key, encrypted input payload, iv (used for encrypting input payload), the authentication-tag and JWE.

## Use cases
1. Assert oneâ€™s identity, given that the recipient of the JWE trusts the asserting party.
2. Transfer data securely between interested parties over a unsecured channel.

## Setup
1. For these plugin, we need a RSA private key already imported in DSM, and its corresponding public key as a certificate which the user should provide as input.

## Input/Output JSON object format
1. **`payload`** corresponds to input data, which is first signed and then encrypted.
2. **`key`** is the name of `RSA` private key which should be already imported in `DSM`. This is used for signing the payload.
3. **`cert`** contains the contents of the certificate (`pem` file) in base64 encoding. This is used to encrypt and verify the signature.

## Example usages
Sample Input format: (The certificate value should be supplied as base64 encoded string)
```
{
        "payload" : "hello world",
        "key" : "keyname",
		"cert" : "...."
}
```

Sample Output format:
```
    {
        header : header,
        encrypted_key : encrypt_trans_key,
        cipher : cipher,
        iv : iv,
        tag : digest,
        jwe : jwe,
    }
```

## References
1. https://tools.ietf.org/html/rfc7515
2. https://tools.ietf.org/html/rfc7516