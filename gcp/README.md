# FORTANIX SELF-DEFENDING KMS Google Cloud KMS BRING YOUR OWN KEY (BYOK) PLUGIN

## Introduction

The cloud services provide many advantages but the major disadvantage of cloud providers has been security because physically your data resides with the cloud provider. To keep data secure in a cloud provider environment, enterprises use encryption. So securing their encryption keys become significantly important. Bring Your Own Key (BYOK) allows enterprises to encrypt their data and retain control and management of their encryption keys. This plugin provides an implementation to use the Google cloud BYOK model.

## Requirenment

- Fortanix Self-Defending KMS Version >= 3.17.1330

## Use cases

The plugin can be used to

- Push Fortanix Self-Defending KMS key in Google Cloud KMS
- List Fortanix Self-Defending KMS Google Cloud BYOK key
- Rotate Fortanix Self-Defending KMS Google Cloud BYOK key
- Disable Google Cloud BYOK key from Fortanix Self-Defending KMS
- Enable Google Cloud BYOK key from Fortanix Self-Defending KMS
- Delete Google Cloud BYOK key from Fortanix Self-Defending KMS
- Reimport key material from Fortanix Self-Defending KMS to Google Cloud CMK


## Setup

- Log in to Google Cloud portal
- Create Google Cloud KMS Service Account and Secret Key
- Create Google Cloud IAM Role for Cloud KMS Admin
- Attach IAM Role to Service Account

## Input/Output JSON object format

### Configure operation

This operation configures Google Cloud Service Account secret Key in Fortanix Self-Defending KMS and returns a UUID. You need to pass this UUID for other operations. This is a one time process.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `configure`.
* `secret_key`: Google Cloud secret key containing the type, project, client_email and private_key

#### Example

Input JSON
```
{
  "operation": "configure",
  "location": "us-east1",
  "key_ring": "gcp-keyring",
  "secret_key": {
    "type": "service_account",
    "project_id": "project-id-102203",
    "client_email": "sdkms-byok@project-id-102203.iam.gserviceaccount.com",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkggSiAgEAAdIk2bywgHRaKg==\n-----END PRIVATE KEY-----\n"
  }
}
```
Output JSON
```
{
  "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
}
```

### Create operation

This operation will create an AES-256 key in Fortanix Self-Defending KMS and import it in Google Cloud KMS.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `create`.
* `name`: Name of the key
* `secret_id`: The response of `configuration` operation. 
* `location`: Optional. Region or location. Example: global or us-east1.
* `key_ring`: Optional. Name of Google Cloud KMS key ring.
* `disable_previous`: true|false. Previous key version state change.

#### Example

Input JSON

```
{
  "operation": "create", 
  "name": "test-key",
  "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
  "labels": { "source": "fortanix-byok" }
}
```

Output JSON
```
{
  "creator": {
    "plugin": "37d99d30-85cc-43fb-aa03-b12d25def766"
  },
  "kid": "c48db54f-075e-4500-9900-715eb74c5349",
  "acct_id": "0491fa2d-0c59-4daf-b293-8859c7d491d0",
  "custom_metadata": {
    "GCP_KEY_ID": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key",
    "GCP_CREATED": "2020-09-21T20:58:15.849005292Z",
    "GCP_KEY_VERSION": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key/cryptoKeyVersions/1",
    "GCP_UPDATED": "2020-09-21T20:52:12.282941162Z"
  },
  "aes": {
    "random_iv": null,
    "key_sizes": null,
    "cipher_mode": null,
    "fpe": null,
    "iv_length": null,
    "tag_length": null
  },
  "kcv": "a90519",
  "activation_date": "20200921T215621Z",
  "key_size": 256,
  "key_ops": [
    "ENCRYPT",
    "DECRYPT",
    "EXPORT",
    "APPMANAGEABLE"
  ],
  "group_id": "0f1ffedd-9a23-4dc8-9a47-952e50bb1b71",
  "lastused_at": "19700101T000000Z",
  "never_exportable": false,
  "obj_type": "AES",
  "enabled": true,
  "compliant_with_policies": true,
  "origin": "FortanixHSM",
  "name": "test-key",
  "created_at": "20200921T215621Z",
  "public_only": false,
  "state": "Active"
}
```

### List operation

This operation will list all the BYOK keys from a Google Cloud KMS key ring.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `list`.
* `secret_id`: The response of `configuration` operation. 

#### Example

Input JSON
```
"
{
  "operation": "list", 
  "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
}
"
```

Output JSON
```
{
  "cryptoKeys": [
    {
      "createTime": "2020-09-21T02:26:48.718637503Z",
      "versionTemplate": {
        "protectionLevel": "SOFTWARE",
        "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"
      },
      "purpose": "ENCRYPT_DECRYPT",
      "name": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/Fortanix-GCP-BYOKey",
      "labels": {
        "source": "fortanix-byok"
      }
    },
    {
      "labels": {
        "source": "fortanix-byok"
      },
      "createTime": "2020-09-21T20:58:15.849005292Z",
      "primary": {
        "importTime": "2020-09-21T21:20:25.960522434Z",
        "protectionLevel": "SOFTWARE",
        "importJob": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/importJobs/byok-ftx-plugin-1600721534",
        "state": "ENABLED",
        "name": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key/cryptoKeyVersions/4",
        "createTime": "2020-09-21T21:20:25.935360774Z",
        "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"
      },
      "name": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key",
      "purpose": "ENCRYPT_DECRYPT",
      "versionTemplate": {
        "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
        "protectionLevel": "SOFTWARE"
      }
    }
  ],
  "totalSize": 2
}
```

### Get operation

This operation will retrieve a specific BYOK key from Google Cloud KMS.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `get`.
* `secret_id`: The response of `configuration` operation. 
* `name`: Name of the key  

#### Example

Input JSON
```
{
  "operation": "get", 
  "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
  "name": "test-key",
}
```

Output JSON
```
{
  "primary": {
    "protectionLevel": "SOFTWARE",
    "importTime": "2020-09-21T21:20:25.960522434Z",
    "createTime": "2020-09-21T21:20:25.935360774Z",
    "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
    "name": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key/cryptoKeyVersions/4",
    "importJob": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/importJobs/byok-ftx-plugin-1600721534",
    "state": "ENABLED"
  },
  "labels": {
    "source": "fortanix-byok"
  },
  "createTime": "2020-09-21T20:58:15.849005292Z",
  "purpose": "ENCRYPT_DECRYPT",
  "versionTemplate": {
    "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
    "protectionLevel": "SOFTWARE"
  },
  "name": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key"
}
```

### Rotate operation

This operation will rotate a key in Fortanix Self-Defending KMS as well as in Google Cloud KMS.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `rotate`.
* `secret_id`: The response of `configuration` operation. 
* `name`: Name of the key  
* `key_ring`: Optional. Name of Google Cloud KMS key ring.
* `disable_previous`: Optional. true|false. Previous key version state change.

#### Example

Input JSON
```
{
  "operation": "rotate", 
  "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144",
  "name": "test-key"
}
```

Output JSON
```
{
  "creator": {
    "plugin": "37d99d30-85cc-43fb-aa03-b12d25def766"
  },
  "kid": "c48db54f-075e-4500-9900-715eb74c5349",
  "acct_id": "0491fa2d-0c59-4daf-b293-8859c7d491d0",
  "custom_metadata": {
    "GCP_KEY_ID": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key",
    "GCP_CREATED": "2020-09-21T20:58:15.849005292Z",
    "GCP_KEY_VERSION": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key/cryptoKeyVersions/2",
    "GCP_UPDATED": "2020-09-21T21:56:22.663641162Z"
  },
  "aes": {
    "random_iv": null,
    "key_sizes": null,
    "cipher_mode": null,
    "fpe": null,
    "iv_length": null,
    "tag_length": null
  },
  "kcv": "a90519",
  "activation_date": "20200921T215621Z",
  "key_size": 256,
  "key_ops": [
    "ENCRYPT",
    "DECRYPT",
    "EXPORT",
    "APPMANAGEABLE"
  ],
  "group_id": "0f1ffedd-9a23-4dc8-9a47-952e50bb1b71",
  "lastused_at": "19700101T000000Z",
  "never_exportable": false,
  "obj_type": "AES",
  "enabled": true,
  "compliant_with_policies": true,
  "origin": "FortanixHSM",
  "name": "test-key",
  "created_at": "20200921T215621Z",
  "public_only": false,
  "state": "Active"
}
```

### Disable operation

This operation will disable a Google Cloud KMS key.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `disable`.
* `secret_id`: The response of `configuration` operation. 
* `name`: Name of the key  

#### Example

Input JSON
```
{
  "operation": "disable", 
  "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
  "name": "test-key",
}
```

Output JSON
```
{
  "protectionLevel": "SOFTWARE",
  "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
  "createTime": "2020-09-21T21:20:25.935360774Z",
  "name": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key/cryptoKeyVersions/4",
  "importJob": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/importJobs/byok-ftx-plugin-1600721534",
  "importTime": "2020-09-21T21:20:25.960522434Z",
  "state": "DISABLED"
}
```

### Enable operation

This operation will enable a Google Cloud KMS key that's disabled.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `enable`.
* `secret_id`: The response of `configuration` operation. 
* `name`: Name of the key  

#### Example

Input JSON
```
{
  "operation": "enable", 
  "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
  "name": "test-key",
}
```

Output JSON
```
{
  "importJob": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/importJobs/byok-ftx-plugin-1600721534",
  "protectionLevel": "SOFTWARE",
  "importTime": "2020-09-21T21:20:25.960522434Z",
  "name": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key/cryptoKeyVersions/4",
  "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
  "createTime": "2020-09-21T21:20:25.935360774Z",
  "state": "ENABLED"
}
```
