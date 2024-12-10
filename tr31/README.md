# TR-31
Plugin for wrapping/unwrapping TR-31 key blocks (ANSI X9.143-2021)

## Introduction
This plugin allows to operate on TR-31 key blocks, also known as cryptograms.
It can create cryptograms, e.g., wrap a key already residing in Fortanix DSM
with given TR-31 properties. Additionally, this plugin can also open
cryptograms, e.g., unwrap a cryptogram created elsewhere and import the
underlying key into Fortanix DSM.

## Prerequisites
In order to operate, this plugin needs the Key Block Protection Key
(henceforth "KBPK" - the unwrapping key) of type AES-256 already residing in
Fortanix DSM.

## Create a cryptogram
This operation, labeled "seal", needs a target key and a composed header
with the following ANSI X9.143-2021 attributes:
- Version: Table 1 of [ANSI]. Only value "D" is currently supported.
- Key Usage: Table 2 of [ANSI]
- Algorithm: Table 3 of [ANSI]
- Mode of Use: Table 4 of [ANSI]
- Key Version Number: Table 5 of [ANSI]
- Exportability: Table 6 of [ANSI]
- Key Context: Description in Table 1 of [ANSI]

Example input:
```
{
    "operation": "seal",
    "key_block_protection_key_id": "90850697-2d66-489f-84e8-38b987e4d48e",
    "target_key_id": "10b09192-d036-44ab-ba95-d05bf34a57f4",
    "header": {
        "version": "D",
        "key_usage": "P0",
        "algorithm": "E",
        "mode_of_use": "E",
        "key_version_number": "00",
        "exportability": "E",
        "key_context": "0"
    }
}
```

## Import a cryptogram

This operation takes a KBPK, a cryptogram, and a Sobject template. It opens
the cryptogram and imports the Sobject into DSM with the given template
values.

Example input:
```
{
    "operation": "open",
    "key_block_protection_key_id": "90850697-2d66-489f-84e8-38b987e4d48e",
    "cryptogram": "D0240P0EE00E0000A839F57FF82C76859B184F1EB1A3DB4E9931819F32EFF9241E9CDB5DF2C0E122ACA0AF299E36EF2BB9D373B6D04A791C584C882EF57A7C060E4E1881C76213269568D0E77F1EE459395FBE5111A86F8E03E17D4FF7E8CFC00FB4B140E382DE6FB5F2DAF791C889A015090B9F331A1DAB",
    "sobject_template": {
        "transient": true
    }
}
```

## References

[ANSI]: ANSI X9.143-2022 INTEROPERABLE SECURE KEY BLOCK SPECIFICATION

### Release Notes
 - 1.0 Initial release
