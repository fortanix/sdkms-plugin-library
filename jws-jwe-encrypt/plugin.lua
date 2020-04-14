-- Name:JWS+JWE Encrypt
-- Version: 1.0
-- Description:## Short Description
-- This plugin generates a **JSON Web Encryption (JWE)** from the **JSON Web Signature (JWS)**, which is constructed using the user's input payload. 
--
-- ### ## Introduction
-- This plugin, performs encrypt using JWE standards:  enc:  A256CBC-HS512 alg:  RSA-OAEP-256.
-- 
-- This plugin performs the following steps:
-- 
-- 1. It generates a JWS from the `payload`.
-- 2. Generates a header for JWS containing `alg` and `typ`, as:
--   ```
--     {typ : "JWT", "alg" : "RS256"}
--   ```
-- 3. Encodes header and input payload to the Base64URL format.
-- 4. Constructs the JWS Signing input by concatenating header and payload.
-- 5. Sign the above constructed `Jws Signing input` by RSA private key (provided in input) using SHA-256 and mode as PKCS1-v1_5.
-- 6. Encodes the signature in the Base64URL format and constructs JWS by concatenating header, payload, and signature by using `"."` as a separator. It will use this `jws` as input payload to `JWE`.
-- 7. Generate the header for JWE, containing `alg, enc, typ`.
--     ```
--         {alg = "RSA-OAEP-256", enc = "A256CBC-HS512", typ = "JWT"}
--     ```
-- 8. Generate an exportable `transient` `AES` key of size `256` bits and an exportable `transient` `HMAC` key of size `256` bits.
-- 9. Encrypts the above generated JWS using the transient AES key in `CBC` mode.
-- 10. Generate `aad` using the `header` and `al` to store the size of `aad`.
-- 11. Creates an input payload for HMAC consisting of `aad, iv, cipher, al`.
-- 12. Creates a HMAC of the payload created above using HMAC key using `SHA-512` as the hashing algorithm.
-- 13. Truncate the digest generated above to half the length and use as authentication-tag.
-- 14. Import the `certificate` as a transient key.
-- 15. Encrypt the combined transient AES key and HMAC key with the `certificate` given as input, using `OAEP_MGF1_SHA256` as the mode and `RSA` is the algorithm.
-- 16. Returns the header, encrypted transient key, encrypted input payload, iv (used for encrypting input payload), the authentication-tag and JWE.
-- 
-- ## Use cases
-- 
-- 1. Assert one’s identity, given that the recipient of the JWE trusts the asserting party.
-- 2. Transfer data securely between interested parties over a unsecured channel.
-- 
-- ## Setup
-- 
-- 1. For these plugin, we need a RSA private key already imported in SDKMS, and its corresponding public key as a certificate which the user should provide as input.
-- 
-- ## Input/Output JSON object format
-- 
-- 1. **`payload`** corresponds to input data, which is first signed and then encrypted.
-- 2. **`key`** is the name of `RSA` private key which should be already imported in `SDKMS`. This is used for signing the payload.
-- 3. **`cert`** contains the contents of the certificate (`pem` file) in base64 encoding. This is used to encrypt and verify the signature.
-- 
-- ## Example usages
-- 
-- Sample Input format: (The certificate value should be supplied as base64 encoded string)
-- ```
-- {
--         "payload" : "hello world",
--         "key" : "keyname",
-- 		"cert" : "...."
-- }
-- ```
-- 
-- Sample Output format:
-- ```
--     {
--         header : header,
--         encrypted_key : encrypt_trans_key,
--         cipher : cipher,
--         iv : iv,
--         tag : digest,
--         jwe : jwe,
--     }
-- ```
-- 
-- ## References
-- 
-- 1. https://tools.ietf.org/html/rfc7515
-- 2. https://tools.ietf.org/html/rfc7516
-- 
-- ### Release Notes
-- - Initial release

--[[
    {
        "payload" : "hello world",
        "key" : "rsakey",
		"cert" : "MIIDRTCCAi2gAwIBAgIJANWt2yo+EcuAMA0GCSqGSIb3DQEBCwUAMFQxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxDTALBgNVBAMMBERFTU8wHhcNMTkxMDEwMjExNDQ4WhcNMTkxMTA5MjExNDQ4WjBUMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMQ0wCwYDVQQDDARERU1PMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsNkNXpiQfvOBSTBRvvMoJBWIL7ucyC3LBXX4kybqLQHeI/FcrbfuhQ+PCY67A7cMjhUCRVvv/NL3I1o7JeBraFnJC1R8+RZ8aD3SqweusOOxFFibMgveaQRQIh7C9Dc9sdn7wgnrBCP6kDk8vTwYylUd5v0NBXZcuAC89dHjYLMQCVGQ0s5qTFxUBhs0MXjKgIZm/0gqkbqln78NYsNuIVBt8TBEYTbpBC4CAtJzuNcOKpRfsYyGk/HAG8kiaGnQcRoa3fZZBXGZbjvn7q7qRd9l/Okvov4MqvAOjxErh4v+2smDp/RQhxG1khksYjVU1U5168of8XkveFvm/Q6dVwIDAQABoxowGDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DANBgkqhkiG9w0BAQsFAAOCAQEAm4WT2Phx+t00pfKRy3AByZyewqTwHzyuY3UCYGi+vJ4l/YmrPrKI2FUU/QQe5IYb8b07+eV54vpqGcdcif0u7eRcjYGnTz6vxQPsUnDj8SVgjDihGxJGb+f6BonBT8IHQM+JXKWjbWaPK7aWMjsbIL1X+IrY1Anx+GX99AmuYskC8Tq0JpIuRSrNnJoC1zA5+U7saateh3iSBHdSqQVCSjcKwblmxEz5e6lQ8OPQzpnf7iblMbvdDyTWTSIEZ5JO3C+byQ98OheW6mrJupw8rPXdDdQClzn2ZhoNxhWrQsWcvfIXJAo/xbeVbEzJrnqbTcDFR/fwiSR6hgH4mUUo1Q=="
    }
]]--
function base64url(str)
    local blob = Blob.from_bytes(str)
    return blobToBase64url(blob)
end

function blobToBase64url(input)
    base64 = input:base64()
    local url = base64:gsub("+", "-")
    url = url:gsub("/", "_")
    url = url:gsub("=", "")
    return url
end

function generateAD(header)
    local object = "\"alg\":"..header.alg..",\"typ\":"..header.typ
    local base64string = base64url(object)
    return Blob.from_bytes(base64string):base64()
end

function truncateDigest(digest)
    local num = #digest
    return digest:slice(1, num/2)
end

--   enc:  A256CBC-HS512 alg:  RSA-OAEP-256
function generateHeader()
    return {alg = "RSA-OAEP-256", enc = "A256CBC-HS512", typ = "JWT"}
end

function computeLength(aad)
    local num = #aad
    local bitlength = num * 8
    a = {0,0,0,0,0,0,0,0}
    for i = 8, 1, -1 do
        a[i] = bitlength % 256
        bitlength = bitlength // 256
    end
  	local s = ""
  	for i = 1, 8 do
    	s = s.. string.char(a[i])
  	end
    return s
end

function generateJws(input)
    header = "{\"typ\":\"JWT\",\"alg\":\"RS256\"}"
    jws_header = base64url(header)
    jws_payload = base64url(input.payload)
    jws_signing_input = jws_header .. "." .. jws_payload

    local sobject = assert(Sobject { name = input.key })
    local sign_response = assert(sobject:sign{data = Blob.from_bytes(jws_signing_input), hash_alg = 'SHA256', mode = { PKCS1_V15 = {} } } )
    local jws_signature_value = blobToBase64url(sign_response.signature)
    local jws = jws_header.."."..jws_payload.."."..jws_signature_value
    return jws
end

function constructJwe(encrypted_key, iv, cipher, tag)
    local jwe = blobToBase64url(encrypted_key).."."..blobToBase64url(iv).."."..blobToBase64url(cipher).."."..blobToBase64url(tag)
    return jwe
end

function processCert(input)
    local result = input.cert
    result = string.gsub(result, "\n", "")
    result = string.sub(result, 28)
    result = string.sub(result, 1, -26)
    return result
end

function createCert(input)
    local value = processCert(input)
    local sobject = assert(Sobject.import { name = "my key", obj_type = "CERTIFICATE", value = value, transient = true})
    return sobject
end

function run(input)
    local header = generateHeader()
    local jws = generateJws(input)
    local aes_key = assert(Sobject.create { name = "aes-key", obj_type = "AES", key_size = 256, transient = true, key_ops = {'EXPORT', 'ENCRYPT', 'DECRYPT'}})
    local hmac_key = assert(Sobject.create { name = "hmac-key", obj_type = "HMAC", key_size = 256, transient = true, key_ops = {'EXPORT', 'MACGENERATE', 'MACVERIFY'}})
    local encrypt_response = assert(aes_key:encrypt { plain = Blob.from_bytes(jws), mode = 'CBC'})
    local iv = encrypt_response.iv
    local cipher = encrypt_response.cipher
    local aad = generateAD(header)
    local al = computeLength(aad)
    local hmac_input_blob = Blob.from_bytes(aad) .. iv .. cipher .. Blob.from_bytes(al)
    local mac_response = assert(hmac_key:mac { data = hmac_input_blob:base64(), alg = 'SHA512' })
    local digest = truncateDigest(mac_response.mac)
    local sobject = createCert(input)
    local export_aes_key = aes_key:export().value
    local export_hmac_key = hmac_key:export().value
    local encrypt_key_response = assert(sobject:encrypt { plain = export_aes_key .. export_hmac_key, mode = 'OAEP_MGF1_SHA256', alg='RSA' })
    local jwe = constructJwe(encrypt_key_response.cipher, iv, cipher, digest)
    return {header = header, encrypted_key = blobToBase64url(encrypt_key_response.cipher), cipher = blobToBase64url(cipher), iv = blobToBase64url(iv), tag = blobToBase64url(digest), jwe = jwe}
end

