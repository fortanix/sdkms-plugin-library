# PKCS #10 Certification Request

## Introduction
This plugin can produce PKCS #10 Certification Request for a asymmetric security object
in DSM. The sobject needs to be in a group to which this plugin has access.
See [RFC 2986](https://datatracker.ietf.org/doc/html/rfc2986) for more details about PKCS #10.

## Input/Output

This plugin accepts a JSON object with the following fields as input:

* `subject_dn`: a map of OIDs to values
* `subject_key`: the name of the subject key security object
* `attributes` (optional): a map of OIDs to an object which contains more information about that attribute.
* `hash_alg` (optional): hash algorithm used before CSR signing.

It returns the newly generated certificate signing request (CSR) in PEM format encoded as a JSON string.

## Example Usage
Assuming there exists an sobject of type RSA/EC named "Subject key", following will produce a CSR:

```json
{
  "subject_dn": {
    "CN": "localhost",
    "OU": [
      "Testing",
      "Testing2"
    ]
  },
  "subject_key": "Subject key",
  "attributes": {
    "extensionRequest": {
      "subjectAlternativeName": {
        "dns_names": [
          "example.com",
          "example2.com"
        ],
        "ip_addresses": [
          "127.0.0.1",
          "2001:db8:3333:4444:5555:6666:7777:8888",
          "2001:db8:3333:4444:5555:6666:1.2.3.4",
          "::1234:5678:1.2.3.4"
        ],
        "critical": true
      },
      "<any_other_extension_oid>": {
        "der_value": "<base64_der_value>"
      }
    },
    "<any_other_attribute_oid>": {
      "der_values": ["<base64_der_value_1>", "<base64_der_value_2>", ...]
    }
  }
}
```

As shown above, for some attributes, special syntax is available (only `extensionRequest` for now). Value for other attributes
can be specified by `der_values`. Also, if `der_values` is specified for attributes with special syntax support (like `extensionRequest`),
that special syntax will be ignored and `der_values` will be prioritised. `der_values` is an array of base64 DER encoded elements for the particular attribute.
The input is a sequence because PKCS #10 RFC allows an attribute to have multiple values. Whether it makes sense to have multiple values or not
depends on that particular attribute. Like `extensionRequest` only allows a single value.

Also, special syntax could be available for extensions specified within `extensionRequest` attribute. If not, `der_value` can be
used and will also be prioritised over special syntax like above. Currently, special syntax in extensions is only supported for subjectAlternativeName
as shown above and it only supports `dns_names` and `ip_addresses` for now.

## References
- [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280)
- [RFC 2986](https://datatracker.ietf.org/doc/html/rfc2986)
- [RFC 2985](https://datatracker.ietf.org/doc/html/rfc2985)

