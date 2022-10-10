# X.509 TBS CA

## Introduction

X.509 certificates are a key element of many security architectures. It cryptographically
ties a public key to the issuer of the certificate. Companies may wish to use their own input format.
This example plugin shows the flexibility of Fortanix's plugin framework. In this case a basic JSON 
structure is accepted as input. After the input passes a user-specified verification function, any
desired fields can be added and a valid X509 certificate is created. The signed certificate is returned 
in PEM format.

## Use Cases

X.509 certificates are used in a wide variety of applications:

 - Webservers use X.509 certificates as part of TLS to authenticate their identity
 - IPsec uses it to authenticate peers
 - Code signing systems such as Microsoft Authenticate enable verification of vendors of computer programs
 - etc.


## Input/Output JSON Object Format

The input is a JSON map with the following fields:

* `subject_key`: the name of the key that will be included in the certificate
* `issuer_cert`: the name of the issuer cert stored in SDKMS
* `issuer_key`: the name of the issuer key stored in SDKMS
* `cert_lifetime`: the lifetime of the certificate in seconds
* `subject_dn`: a map of OIDs to values

## Example Usages

Input:
```
{
  "issuer_cert": "my CA cert",
  "issuer_key": "my CA key",
  "subject_key": "my server key",
  "cert_lifetime": 86400,
  "subject_dn": { "CN": "localhost", "OU": "Testing" }
}
```

Output:
```
-----BEGIN CERTIFICATE-----
MIIDPTCCAiWgAwIBAgIUJzh5GdpFnsYeDTY3qc9xv6ZJmBQwDQYJKoZIhvcNAQEL
BQAwJTEQMA4GA1UEAxMHVGVzdCBDQTERMA8GA1UEChMIRm9ydGFuaXgwHhcNMjAw
NDE1MTQxNTUzWhcNMjAwNDE2MTQxNTUzWjAlMREwDwYDVQQKDAhGb3J0YW5peDEQ
MA4GA1UECwwHVGVzdGluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ANI/C8XizogQbWSeYYmxlwrpXYblfHOjQI5w8JhNFA9a5z+K3r94ju22Nf9CYeBL
27oSaS1Q0fNc6izTaV27uGis2X903J3tX4JLusdLeKqxsXwkLy5u8SsjT13HGBi9
WdPnKLcKS+gX/zf3wOYdRcWILfRa6AxQzAL69Awk2SBW+EbTgo0LlWko9oK1uV+s
U1dmpljq0ngRIgD2KUrb2g23cOS954AnkrsI28J4twbv7/Pw3xmrVY+2AU7haVqO
fM18T0Vb8MYmT9tuUD+oWdj3AzFWNiVCUiQh6VI7WvVLFUkKIsW1IyRShoiWKcqr
ZzCBexmM71I02gvqYv00E58CAwEAAaNlMGMwGQYDVR0OBBIEEDFzdjRCbnY3L1k0
NmNOK04wDwYDVR0TAQH/BAUwAwEBADAQBgNVHSAECTAHMAUGAyoDBDAjBgNVHSME
HDAagBjuPJ14dyS2Lnt2/V/cMHPMTfBWiuvjOOgwDQYJKoZIhvcNAQELBQADggEB
ANKWKbGJlfzf6JhbvHWHlXmJVbyBN8GKWYJZbEZjNdFrv8bbXPhHHYcczMZ1ua5I
zzNR/2o6iP2PzBKhBa57jzxiam+9b0UPv/tpekj/i8bUVg6gCGO6SEq5/WRmEDcO
DoIli8UDSHayZMFdqaL/orGSXsgBOCjvbLxGfjJm3KCDzFOZoxuBcOPnhxeLLRts
CQK5eiiwcx+2gCsU+Jg/j6kpLQpZC96IiHeJPSKaXIkehMyh6UuDGYbtCuEUXtcj
mCCZAbXsajBfVa+YM42zD+FOQ1pjh4JTc8q3gPXecmQaIcK6LXoGOOUZ+z5vNhbb
gWph2EGdaFrf1FCrcf5QKEA=
-----END CERTIFICATE-----
```

If same attribute needs to be specified multiple times in `subject_dn` (like multiple "OU"),
a list can be passed instead of a string. For example:

```json
{
  "issuer_cert": "my CA cert",
  "issuer_key": "my CA key",
  "subject_key": "my server key",
  "cert_lifetime": 86400,
  "subject_dn": { "CN": "localhost", "OU": ["Testing", "TestingAgain"] }
}
```

## References

 - [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.txt)
