# SAP DATA CUSTODIAN BRING YOUR OWN KEY (BYOK) PLUGIN

## Introduction

The cloud services provide many advantages but the major disadvantage of cloud providers has been security because physically your data resides with the cloud provider. To keep data secure in a cloud provider environment, enterprises use encryption. So securing their encryption keys become significantly important. Bring Your Own Key (BYOK) allows enterprises to encrypt their data and retain control and management of their encryption keys. This plugin provides an implementation to use the Data Custodian BYOK model.

## Requirement

- Fortanix DSM Version >= 4.2.1528

## Use cases

The plugin can be used to

- Import a Fortanix DSM key (AES or RSA) into Data Custodian
- Rotate a key in Fortanix DSM and import the new key version of an existing key into Data Custodian

Fortanix DSM keys (AES and RSA) can be imported into Data Custodian groups or rotated (if already imported) in both AWS and non-AWS keystore providers.

## Setup

- Create a technical user in data custodian and obtain API Key and Secret for this user
- Create KEK key in Data Custodian and get its Key Id and Version number for Non AWS keystore provider.
- Obtain group id of the group in Data Custodian where you want to import keys

## Input/Output JSON object format

### Configure operation

This operation configures Data Custodian Technical User credential in Fortanix DSM and returns a UUID. You need to pass this UUID for other operations. This is a one time process. Configure operation is common for both Non AWS and AWS KMS keystore provider

* `operation`: The operation which you want to perform. A valid value is `configure`.
* `base_url`: Base URL for your Data Custodian instance. Base URL must not contain `/kms/v2/`.
* `api_key`: API key for technical user in Data Custodian
* `secret`: Secret for technical user in Data Custodian. Please note you should `not` have activated technical user's credential and use non activated credential here

#### Example

Input JSON
```
{
   "operation": "configure",
   "base_url": "https://api-kms-v2-preprod.datacustodian.cloud.sap",
   "api_key": "eyJjcmVkZ.....VkNzkzNjEifQ==",
   "secret": "EIVa......CYa8"
}
```

Output JSON
```
{
  "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
}
```

### Import operation

Import operation will create a new key (RSA or AES) in Fortanix DSM and import it into Data Custodian. The key with the name provided should not already exist in DSM.

#### Parameters

* `operation`: The operation which you want to perform. A valid values is `import`
* `secret_id`: The response of `configuration` operation
* `is_exportable`: Whether the imported key in Data Custodian should be exportable or not. Valid values for this are true or false. This parameter applies to non-AWS KMS keystore provider
* `datacustodian_role`: This is an optional parameter. This specified the Data Custodian role that should be given to the imported key. If not specified, role is set as UNSPECIFIED. For a complete list of value for role, please check Data Custodian documentation
* `datacustodian_group_id`: Group Id of the group in Data Custodian where this key will be imported.This is required to determine the provider of the target key in Data Custodian.
* `target_key_type`: Key type of the target key that you want to generate in DSM and import into Data Custodian. Valid values are RSA and AES
* `target_key_name` : Name of the target key. This name will be used for the key in DSM and in Data Custodian
* `target_key_description`: Description of the key. This description will be added to the imported key in Data Custodian
* `target_key_size`: Size of target key. For RSA key type valid values are 2048, 3072, 4096 and for AES key type valid values are 128, 192 and 256
* `kek_key_id`: Id of the KEK in Data custodian. This key must exist in Data Custodian. BYOK process will download the public key from Data Custodian and import into DSM for wrapping key material. This parameter applies to non-AWS KMS keystore providers
* `kek_key_version`: Version number of the KEK in Data Custodian. This parameter applies to non-AWS KMS keystore providers
* `target_key_operations`: This is an optional parameter for Non AWS keystore provider. If not specified, default values for the key type are used. Valid values for RSA key type are "ENCRYPT", "DECRYPT", "SIGN", "VERIFY", "WRAP", "UNWRAP" and valid values for AES key type are "ENCRYPT", "DECRYPT", "WRAP", "UNWRAP". This is a required parameter for AWS KMS keystore provider. The valid values for RSA key type are ["ENCRYPT", "DECRYPT"] and ["SIGN", "VERIFY"] and valid values for AES key type are ["ENCRYPT", "DECRYPT"].
* `kek_key_size` : The wrapping key size is required to create wrapping keys for target keys in the AWS KMS keystore provider. Valid values are 3072 and 4096. RSA wrapping key is generated for the target key created in the AWS KMS keystore provider.

#### Example for Non AWS keystore provider

Input JSON without specifying key operations (use default key operations)
```
{
  "operation": "import",
  "secret_id": "2b4a35dc-511d-4d1c-ad30-29e57cae7686",
  "is_exportable": false,
  "datacustodian_group_id": "5069b28d-a01c-4bc0-97ce-c19064d056c0",
  "target_key_type" : "RSA",
  "target_key_name": "test-imported-key-20220517-01",
  "target_key_description": "Test - This is a test key for BYOK from DSM",
  "target_key_size": 2048,
  "kek_key_id": "a58860d9-e832-433d-9c33-d310dd201adc",
  "kek_key_version": 0
}
```

Input JSON with specific key operations
```
{
  "operation": "import",
  "secret_id": "2b4a35dc-511d-4d1c-ad30-29e57cae7686",
  "is_exportable": true,
  "datacustodian_group_id": "5069b28d-a01c-4bc0-97ce-c19064d056c0",
  "target_key_type" : "RSA",
  "target_key_name": "test-imported-key-20220517-20",
  "target_key_description": "Test - This is a test key for BYOK from DSM",
  "target_key_size": 2048,
  "target_key_operations": ["SIGN", "VERIFY"],
  "kek_key_id": "a58860d9-e832-433d-9c33-d310dd201adc",
  "kek_key_version": 0
}
```

Output JSON
```
{
  "result": {
    "exportable": true,
    "id": "e89b3f06-0cf0-4e40-ba31-1237e638cc56",
    "name": "test-imported-key-20220517-20",
    "keystoreContext": {
      "customerHeld": false
    },
    "role": "UNSPECIFIED",
    "enabled": true,
    "groupId": "5069b28d-a01c-4bc0-97ce-c19064d056c0",
    "meta": {
      "primaryVersion": 0,
      "beingRestored": false,
      "templateGenerated": false,
      "lastUsed": null,
      "creatorName": "Txxx@service.datacustodian.cloud.sap",
      "creatorId": "7a869e8c-3b19-4e10-8db8-c0864ed79361",
      "imported": true,
      "created": "2022-05-17T04:42:13.151180",
      "totalVersions": 1
    },
    "size": 2048,
    "description": "This is a test key for BYOK from DSM",
    "type": "RSA",
    "operations": [
      "DECRYPT",
      "ENCRYPT",
      "SIGN",
      "UNWRAP",
      "VERIFY",
      "WRAP"
    ]
  }
}
```

#### Example for AWS keystore provider

Input JSON 
```
{
  "operation": "import",
  "secret_id": "a1b2c3d4-e5f6-7890-ab12-cd34ef56gh78",
  "datacustodian_group_id": "12ab34cd-56ef-78gh-90ij-klmn123op456",
  "target_key_type" : "RSA",
  "target_key_name": "test-imported-key-20250313-01",
  "target_key_description": "Test - This is a test key for BYOK from DSM",
  "target_key_size": 3072,
  "target_key_operations": ["ENCRYPT", "DECRYPT"],
  "kek_key_size" : 4096
}
```
Output JSON
```
{
  "kek_key_id": "abcd5678-ef90-1234-gh56-ijkl7890mnop",
  "result": {
    "id": "9f8e7d6c-5b4a-3210-9876-5432abcd1234",
    "name": "test-imported-key-20250313-01",
    "type": "RSA",
    "keystoreContext": {
      "customerHeld": false,
      "nativeId": "arn:aws:kms:xxxxxxxxx:xxxxxxxxx:alias/xxxxxxxxxxxxxxx-primary"
    },
    "size": 3072,
    "operations": [
      "DECRYPT",
      "ENCRYPT"
    ],
    "role": "UNSPECIFIED",
    "enabled": true,
    "description": "Test - This is a test key for BYOK from DSM",
    "meta": {
      "templateGenerated": false,
      "imported": true,
      "totalVersions": 1,
      "created": "2025-03-12T23:03:04",
      "expired": false,
      "lastModified": "2025-03-12T23:03:08",
      "beingRestored": false,
      "primaryVersion": 0
    },
    "exportable": false,
    "groupId": "12ab34cd-56ef-78gh-90ij-klmn123op456",
    "state": "ENABLED"
  }
}
```
The returned result includes the successful API response for importing the key from Fortanix DSM to Data Custodian, along with the id of the wrapping key created for the target key in the AWS KMS keystore provider required as a parameter in rotate operation.

### Rotate operation

Rotate operation will rotate an existing key (RSA or AES) in Fortanix DSM and import the new key into Data Custodian. For rotate operation the key specified by target_key_name must already exist in DSM and the key specified by datacustodian_key_id must already exist in Data custodian.

#### Parameters

* `operation`: The operation which you want to perform. A valid values is `rotate`
* `secret_id`: The response of `configuration` operation
* `datacustodian_key_id`: Key Id of key in Data Custodian which needs to be rotated 
* `datacustodian_group_id`: The Group ID of the Data Custodian group where the target key will be rotated and the newly rotated key will be imported. This is required to determine the provider of the target key in Data Custodian.
* `target_key_name` : Name of the target key. This name will be used for the key in DSM and in Data Custodian
* `kek_key_id`: Id of the KEK in Data custodian. This key must exist in Data Custodian. BYOK process will download the public key from Data Custodian and import into DSM for wrapping key material. For target key created in AWS KMS keystore provider the KEK will be rotated with a new version as the public key blob is only valid for 24 hours per AWS’s policy.
* `kek_key_version`: Version number of the KEK in Data Custodian. This parameter applies to non AWS KMS keystore provider 

#### Example for Non AWS KMS keystore provider

Input JSON 
```
{
  "operation": "rotate",
  "secret_id": "2b4a35dc-511d-4d1c-ad30-29e57cae7686",
  "datacustodian_key_id": "2504681e-cfd2-44ee-ad63-66211560cc62",
  "target_key_name": "test-imported-key-20220517-aes-01",
  "kek_key_id": "a58860d9-e832-433d-9c33-d310dd201adc",
  "kek_key_version": 0
}
```

Output JSON
```
{
  "result": {
    "operations": [
      "DECRYPT",
      "ENCRYPT",
      "UNWRAP",
      "WRAP"
    ],
    "meta": {
      "totalVersions": 3,
      "creatorId": "7a869e8c-3b19-4e10-8db8-c0864ed79361",
      "templateGenerated": false,
      "primaryVersion": 2,
      "created": "2022-05-18T00:09:58",
      "imported": true,
      "lastUsed": null,
      "beingRestored": false,
      "creatorName": "Txxxx@service.datacustodian.cloud.sap"
    },
    "groupId": "5069b28d-a01c-4bc0-97ce-c19064d056c0",
    "name": "test-imported-key-20220517-aes-01",
    "type": "AES",
    "description": "This is a test key for BYOK from DSM",
    "id": "2504681e-cfd2-44ee-ad63-66211560cc62",
    "keystoreContext": {
      "customerHeld": false
    },
    "size": 256,
    "exportable": true,
    "enabled": true,
    "role": "UNSPECIFIED"
  }
}
```
#### Example for AWS KMS keystore provider

Input JSON 
```
{
  "operation": "rotate",
  "secret_id": "a1b2c3d4-e5f6-7890-ab12-cd34ef56gh78",
  "datacustodian_key_id": "9f8e7d6c-5b4a-3210-9876-5432abcd1234",
  "datacustodian_group_id": "12ab34cd-56ef-78gh-90ij-klmn123op456",
  "target_key_name": "test-imported-key-20250313-01",
  "kek_key_id": "abcd5678-ef90-1234-gh56-ijkl7890mnop"
}
```
Output JSON
```
{
  "result": {
    "operations": [
      "SIGN",
      "VERIFY"
    ],
    "meta": {
      "lastModified": "2025-03-12T23:03:08",
      "imported": true,
      "beingRestored": false,
      "created": "2025-03-12T23:03:04",
      "expired": false,
      "templateGenerated": false,
      "totalVersions": 2,
      "primaryVersion": 1
    },
    "type": "RSA",
    "keystoreContext": {
      "nativeId": "arn:aws:kms:xxxxxxxxx:xxxxxxxxx:alias/xxxxxxxxxxxxxxx-primary",
      "customerHeld": false
    },
    "name": "test-imported-key-20250313-01",
    "exportable": false,
    "groupId": "12ab34cd-56ef-78gh-90ij-klmn123op456",
    "description": "Test - This is a test key for BYOK from DSM",
    "role": "UNSPECIFIED",
    "enabled": true,
    "state": "ENABLED",
    "id": "9f8e7d6c-5b4a-3210-9876-5432abcd1234",
    "size": 2048
  }
}
```
## References
* [Data Custodian REST API](https://api-kms-v2-preprod.datacustodian.cloud.sap/kms/v2/ui/)

## Release Notes
 - Initial release
 - Added Activation step of secret credential to configure operation, enhanced validation and error decoding, improved parameter handling,and  provided better clarity in the key import process.
   Added support to import Fortanix DSM keys (AES and RSA) into Data Custodian groups or rotate the keys (AES and RSA) (if already imported) in `AWS KMS` keystore providers.
