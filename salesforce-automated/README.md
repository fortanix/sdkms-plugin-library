# Automated BYOK for Salesforce Cloud

## Introduction

This plugin implements the Bring your own key (BYOK) model for Salesforce. Using this plugin, you can keep your key inside Fortanix DSM and use Shield Platform Encryption features of Salesforce.

## Use cases

The plugin can be used to

- Upload a key from Fortanix Data Security Manager to Salesforce
- Search tenant secrets (Salesforce encryption keys) using Salesforce Sobject Query Language (SSQL)
- Check current status of any key or key version
- Destroy the archived keys in Salesforce
- Restore a previously destroyed key

## Fortanix Data Security Manager Setup

1. Log in to Fortanix Data Security Manager (https://sdkms.fortanix.com)
2. Create an account in Fortanix Data Security Manager
3. Create a group in Fortanix Data Security Manager
4. Create a plugin in Fortanix Data Security Manager

## Configure Salesforce

1. Create a New Profile under Setup >> Profiles.
   Note: Select â€œManage Encryption Keysâ€ under â€œAdministrative Permissions"
2. Create a New User under Setup >> Users with these inputs â€“
   Name: arbitrarily input
   Profiles: choose the KMS role created in previous step
   Note the credentials to securely import into Data Security Manager secret
3. Create a Connected App under â€œApps >> App Managerâ€ with the following inputs â€“
   Label: arbitrarily input
   Check the â€œEnable OAuth Settingsâ€
   Check the â€œEnable Device Flowâ€ for automated access
   Note the credentials to securely import into Data Security Manager secret
4. Whitelist the Fortanix Data Security Manager application IP range (CIDR)
5. Create a Certificate under â€œSetup >> Certificate and Key Managementâ€ â€“
   Label: arbitrarily input, but note it for later use
   Uncheck the â€œExportable Private Keyâ€
   Check the option to "Use Platform Encryption"
6. Verify the Salesforce credentials
   Client/Consumer Key  (Created in step 3)
   Client/Consumer Secret (Created in step 3)
   OAuth username (Created in step 2)
   OAuth password (Created in step 2)
   Tenant URI
   API version (Fortanix Plugin tested against version 50.0)

## Input/Output JSON object format

### Configure operation

This operation configures Salesforce credentials in Fortanix Data Security Manager and returns a UUID. You need to pass this UUID for other operations. This is a one time process.

### parameters

* `operation`: The operation which you want to perform. A valid value is `configure`.
* `consumer_key`: Consumer Key of the connected app
* `consumer_secret`: Consumer Secret of the connected app
* `username`: OAuth username
* `password`: OAuth password
* `tenant`: Salesforce tenant URI
* `version`: API version (Fortanix Plugin tested against version 50.0)
* `name`: Name of the sobject. This sobject will be created in fortanix Data Security Manager and will have Salesforce credential information

#### Example

Input JSON
```
{
  "operation": "configure",
  "consumer_key": "CBK...................D",
  "consumer_secret": "DMV................D",
  "username" : "ft......x@<your company domain>",
  "password" : "fy....K",
  "tenant"   : "<Salesforce tenant URI>",
  "version"  : "v50.0",
  "name"    : "Salesforce NamedCred Dev"
}
```
Output
```
"3968218b-72c3-4ada-922a-8a917323f27d"
```


### Check operation

This operation is to test whether plugin can import wrapping certificate from salesforce into Fortanix Data Security Manager. (This certificate is required by plugin to authenticate itself to salesforce)

### parameters

* `operation`: The operation which you want to perform. A valid value is `check`
* `secret_id`: The response of `configuration` operation
* `wrapper`: Name of the wrapping certificate in salesforce

#### Example

Input JSON
```
{
  "operation": "check",
  "secret_id": "3968218b-72c3-4ada-922a-8a917323f27d",
  "wrapper"  : "SFBYOK_FTX_Wrapper"
}
```
Output JSON
```
{
  "group_id": "ff2............................c",
  "public_only": true,
  "key_ops": [
    "VERIFY",
    "ENCRYPT",
    "WRAPKEY",
    "EXPORT"
  ],
  "enabled": true,
  "rsa": {
    "signature_policy": [
      {
        "padding": null
      }
    ],
    "encryption_policy": [
      {
        "padding": {
          "OAEP": {
            "mgf": null
          }
        }
      }
    ],
    "key_size": 4096
  },
  "state": "Active",
  "created_at": "20201229T183553Z",
  "key_size": 4096,
  "kid": "6de........................4",
  "origin": "External",
  "lastused_at": "19700101T000000Z",
  "obj_type": "CERTIFICATE",
  "name": "SFBYOK_FTX_Wrapper",
  "acct_id": "ec9.......................7",
  "compliant_with_policies": true,
  "creator": {
    "plugin": "654.......................1"
  },
  "value": "MII........................9",
  "activation_date": "20201229T183553Z",
  "pub_key": "MII......................8",
  "never_exportable": false
}
```


### Query operation

This operation allows you to search tenant secrets (Salesforce encryption keys) using Salesforce Sobject Query Language (SSQL)

### parameters

* `operation`: The operation which you want to perform. A valid value is `query` or `search`
* `secret_id`: The response of `configuration` operation
* `query`: SSQL query
* `tooling`:
* `sandbox`:   To indicate, whether to use test or production tenant.

#### Example

Input JSON
```
{
  "operation": "search",
  "secret_id": "3968218b-72c3-4ada-922a-8a917323f27d",
  "query"   : "select Id, Status, Version from TenantSecret where Type = `Data`",
  "tooling"  : false,
  "sandbox"  : false
}
```
Output JSON
```
{
  "done": true,
  "totalSize": 5,
  "records": [
    {
      "attributes": {
        "type": "TenantSecret",
        "url": "/services/data/v50.0/sobjects/TenantSecret/02G..........O"
      },
      "Status": "ARCHIVED",
      "Id": "02G.............D",
      "Version": 3
    },
    {
      "Version": 1,
      "attributes": {
        "url": "/services/data/v50.0/sobjects/TenantSecret/02G...........W",
        "type": "TenantSecret"
      },
      "Id": "02G...........W",
      "Status": "ARCHIVED"
    },
    {
      "Version": 2,
      "Id": "02G..........O",
      "attributes": {
        "type": "TenantSecret",
        "url": "/services/data/v50.0/sobjects/TenantSecret/02G............O"
      },
      "Status": "ARCHIVED"
    },
    {
      "Id": "02G...........4",
      "attributes": {
        "url": "/services/data/v50.0/sobjects/TenantSecret/02G...........4",
        "type": "TenantSecret"
      },
      "Version": 4,
      "Status": "DESTROYED"
    },
    {
      "attributes": {
        "type": "TenantSecret",
        "url": "/services/data/v50.0/sobjects/TenantSecret/02G............O"
      },
      "Id": "02G..........O",
      "Version": 5,
      "Status": "ACTIVE"
    }
  ]
}
```

### Upload operation

This operation allows you to create a key material in Fortanix Data Security Manager and upload to salesforce

### parameters

* `operation`: The operation which you want to perform. A valid value is `upload`.
* `secret_id`: The response of `configuration` operation
* `wrapper`: Name of the wrapping certificate in salesforce
* `type`: A valid values are `Data|EventBus|SearchIndex`
* `mode`: Key derivation mode. It can be blank which defaults to â€œPBKDF2â€ or can also be "NONE" to disable key derivation in Salesforce.
* `name`: Prefix of the name
* `sandbox`:  To indicate, whether to use test or production tenant.

#### Example

Input JSON
```
{
  "operation": "upload",
  "secret_id": "3968218b-72c3-4ada-922a-8a917323f27d",
  "wrapper"  : "SFBYOK_FTX_Wrapper",
  "type"     : "Data",
  "mode"     :  "",
  "name"     : "Salesforce Data Key",
  "sandbox"  : false
}

```
Output JSON
```
{
  "obj_type": "AES",
  "custom_metadata": {
    "SF_HASH": "ESP.......................=",
    "SF_UPLOAD": "EDF.....................=",
    "SF_WRAPPER": "SFBYOK_FTX_Wrapper",
    "SF_MODE": "",
    "SF_KID": "02G...........O",
    "SF_TYPE": "Data"
  },
  "acct_id": "ec9...................7",
  "creator": {
    "plugin": "654....................1"
  },
  "public_only": false,
  "origin": "Transient",
  "kid": "bb7................3",
  "lastused_at": "19700101T000000Z",
  "activation_date": "20201229T185549Z",
  "key_size": 256,
  "kcv": "b5...9",
  "name": "Salesforce Data Key 20201229T185546Z",
  "state": "Active",
  "enabled": true,
  "key_ops": [
    "EXPORT"
  ],
  "compliant_with_policies": true,
  "created_at": "20201229T185549Z",
  "aes": {
    "tag_length": null,
    "key_sizes": null,
    "random_iv": null,
    "fpe": null,
    "iv_length": null,
    "cipher_mode": null
  },
  "never_exportable": false,
  "group_id": "ff2..............b"
}
```

### status operation

This operation allows you to obtain current status of a salesforce key

### parameters

* `operation`: The operation which you want to perform. A valid value is `status`.
* `secret_id`: The response of `configuration` operation
* `wrapper`: Name of the wrapping certificate in salesforce
* `name`: "name of corresponding sobject in Fortanix Data Security Manager"
* `sandbox`:   To indicate, whether to use test or production tenant.

#### Example

Input JSON
```
{
      "operation" : "status",
      "secret_id": "3968218b-72c3-4ada-922a-8a917323f27d",
      "wrapper"   : "SFBYOK_FTX_Wrapper",
      "name"      : "Salesforce Data Key 20201229T185546Z",
      "sandbox"   : false
}
```
Output JSON
```
{
  "RemoteKeyIdentifier": null,
  "CreatedDate": "2020-12-29T18:55:49.000+0000",
  "SecretValueHash": "ESP........................=",
  "CreatedById": "005..........2",
  "KeyDerivationMode": "PBKDF2",
  "attributes": {
    "url": "/services/data/v50.0/sobjects/TenantSecret/02G..........O",
    "type": "TenantSecret"
  },
  "LastModifiedDate": "2020-12-29T18:55:49.000+0000",
  "IsDeleted": false,
  "SecretValue": "CgM.............................=",
  "SecretValueCertificate": null,
  "Type": "Data",
  "RemoteKeyServiceId": null,
  "Version": 6,
  "Id": "02G..........O",
  "Status": "ACTIVE",
  "SystemModstamp": "2020-12-29T18:55:49.000+0000",
  "RemoteKeyCertificate": null,
  "Source": "UPLOADED",
  "Description": "Salesforce Data Key 20201229T185546Z",
  "LastModifiedById": "005............2"
}
```
### sync operation

This operation allows you to sync Fortanix self-Defending key object with salesforce key.

### parameters

* `operation`: The operation which you want to perform. A valid value is `sync`.
* `secret_id`: The response of `configuration` operation
* `wrapper`: Name of the wrapping certificate in salesforce
* `name`: "name of corresponding sobject in Fortanix Data Security Manager"
* `sandbox`:   To indicate, whether to use test or production tenant.

#### Example

Input JSON
```
{
      "operation" : "sync",
      "secret_id": "3968218b-72c3-4ada-922a-8a917323f27d",
      "wrapper"   : "SFBYOK_FTX_Wrapper",
      "name"      : "Salesforce Data Key 20201229T185546Z",
      "sandbox"   : false
}
```
Output JSON
```
{
  "RemoteKeyCertificate": null,
  "IsDeleted": false,
  "CreatedById": "005..............2",
  "Status": "ACTIVE",
  "Type": "Data",
  "LastModifiedById": "005............2",
  "CreatedDate": "2020-12-29T18:55:49.000+0000",
  "SystemModstamp": "2020-12-29T18:55:49.000+0000",
  "Source": "UPLOADED",
  "SecretValueHash": "ESP.................c",
  "LastModifiedDate": "2020-12-29T18:55:49.000+0000",
  "Version": 6,
  "RemoteKeyServiceId": null,
  "RemoteKeyIdentifier": null,
  "attributes": {
    "type": "TenantSecret",
    "url": "/services/data/v50.0/sobjects/TenantSecret/02G............O"
  },
  "KeyDerivationMode": "PBKDF2",
  "Id": "02G...........O",
  "SecretValueCertificate": null,
  "Description": "Salesforce Data Key 20201229T185546Z",
  "SecretValue": "CgM........................M"
}
```
### destroy operation

This operation allows you to destroy an archived salesforce key.

### parameters

* `operation`: The operation which you want to perform. A valid value is `destroy`.
* `secret_id`: The response of `configuration` operation
* `wrapper`: Name of the wrapping certificate in salesforce
* `name`: "name of corresponding sobject in Fortanix Data Security Manager"
* `sandbox`:   To indicate, whether to use test or production tenant.

#### Example

Input JSON
```
{
      "operation" : "destroy",
      "secret_id": "3968218b-72c3-4ada-922a-8a917323f27d",
      "wrapper"   : "SFBYOK_FTX_Wrapper",
      "name"      : "Salesforce Data Key 20201229T185546Z",
      "sandbox"   : false
}
```
Output
```
output is empty, with http status indicating success.
```
### restore operation

This operation allows you to restore a destroyed salesforce key.

### parameters

* `operation`: The operation which you want to perform. A valid value is `restore`.
* `secret_id`: The response of `configuration` operation
* `wrapper`: Name of the wrapping certificate in salesforce
* `name`: "name of corresponding sobject in Fortanix Data Security Manager"
* `sandbox`:   To indicate, whether to use test or production tenant.

#### Example

Input JSON
```
{
      "operation" : "restore",
      "secret_id": "3968218b-72c3-4ada-922a-8a917323f27d",
      "wrapper"   : "SFBYOK_FTX_Wrapper",
      "name"      : "Salesforce Data Key 20201229T185546Z",
      "sandbox"   : false
}
```
Output
```
output is empty, with http status indicating success.
```
