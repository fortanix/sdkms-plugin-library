# FORTANIX SELF-DEFENDING KMS-AZURE BRING YOUR OWN KEY (BYOK) HSM PLUGIN
---

## Short Description

This plugin implements the Bring your own key (BYOK) HSM model for Azure cloud. Using this plugin you can keep your key inside Fortanix Self-Defending KMS and use BYOK features of Azure key vault.

## Introduction

The cloud services provide many advantages but the major disadvantage of cloud providers has been security because physically your data resides with the cloud provider. To keep data secure in a cloud provider environment, enterprises use encryption. So securing their encryption keys become significantly important. Bring Your Own Key (BYOK) allows enterprises to encrypt their data and retain control and management of their encryption keys. This plugin provides an implementation to use the Azure cloud BYOK model.

## Requirenment

- Fortanix Self-Defending KMS Version >= 3.17.1330

## Use cases

The plugin can be used to

- Push Fortanix Self-Defending KMS key in Azure HSM key vault
- List Azure BYOK key
- Delete key in Fortanix Self-Defending KMS and corresponding key in Azure key vault

## Setup

- Log in to https://portal.azure.com/
- Register an app in Azure cloud (Note down the Application (client) ID, Directory (tenant) ID, and client secret of this app). We will configure this information in Fortanix Self-Defending KMS
- Create a premium Azure key vault
- Add the above app in the `Access Policy` of the above key vault
- Create KEK key in Azure key vault

```
az keyvault key create --kty RSA-HSM --size 2048 --name <KEY-NAME> --ops import --vault-name <KEY-VAULT-NAME>
```

## Input/Output JSON object format

### Configure operation

This operation configures Azure app credential in Fortanix Self-Defending KMS and returns a UUID. You need to pass this UUID for other operations. This is a one time process.

* `operation`: The operation which you want to perform. A valid value is `configure`.
* `tenant_id`: Azure tenant ID
* `client_id`: Azure app ID or client ID
* `client_secret`: Azure app secret

#### Example

Input JSON
```
{ 
   "operation": "configure",
   "tenant_id": "de7becae...88ae6",
   "client_id": "f8d7741...6abb6",
   "client_secret": "SvU...5"
}
```

Output JSON
```
{
  "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
}
```

### create operation

This operation will create an RSA key in Fortanix Self-Defending KMS and impot it in Azure key vault.

#### Parameters

* `operation`: The operation which you want to perform. A valid value is `create`
* `key_name`: Name of the key
* `key_vault`: Azure key vault name
* `kek_key_kid`: Azure Key Exchange Key (KEK) ID
* `secret_id`: The response of `configuration` operation. 

Input JSON
```
{
  "operation": "create",
  "key_name": "test-key",
  "key_vault": "test-hsm-keyvault",
  "kek_key_kid": "https://test-hsm-keyvault.vault.azure.net/keys/test-kek-key/0ffc59a57f664b9fbde6455bd0ed5dd5",
  "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
}
```

Output JSON
```
{
  "result": {
    "key": {
      "n": "5FshKQ_5peJfFcer18EylSxbK94UErV0we_Z-v2EsTjcH_HZBWAUbAF0QJ_q0Qzy6nHA-u0DkAf63YTe3BhuUEU80Qek_pmZjfek4rgE53eSbrEqH7bYVxUEKSye3J_7oR-MMs4YkNqvyenBuLSv7QXZIcPu17zsNhIQrsv0MBdwV_QlewW9QQUeTPLbHUBV7m-r1gdffiINoRcGY9QvHb6dJphoOaNSzddUXm6Y21R7pwI2Lzo3MuEe2nwtOC-z_MW8jdsDNYxua4CipiGOe2Cqqg_wXsZcjpefzYqSGky2y3j7OoG1uHsafRqWatWTj_CHUPr-oII_r2_sGcxBrw",
      "key_ops": [
        "encrypt",
        "decrypt",
        "sign",
        "verify",
        "wrapKey",
        "unwrapKey"
      ],
      "e": "AAEAAQ",
      "kty": "RSA-HSM",
      "kid": "https://test-hsm-keyvault.vault.azure.net/keys/test-key/21dc7692b9184c1ba8e643db8b142356"
    },
    "attributes": {
      "recoveryLevel": "Recoverable+Purgeable",
      "enabled": true,
      "updated": 1593584773,
      "created": 1593584773
    }
  }
```

#### List Key operation

This operation will list all the BYOK keys from azure.

#### Parameters

* `operation`: The operation which you want to perform. A valid value is `list`.
* `key_name`: Name of the key
* `key_vault`: Azure key vault name
* `secret_id`: The response of `configuration` operation. 

#### Example

Input JSON
```
{
  "operation": "list",
  "key_vault": "test-hsm-keyvault",
  "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
}
```

Output JSON
```
{
  "result": {
    "value": [
      {
        "attributes": {
          "recoveryLevel": "Recoverable+Purgeable",
          "enabled": true,
          "updated": 1593587162,
          "created": 1593587161,
          "exp": 1596240000
        },
        "kid": "https://test-hsm-keyvault.vault.azure.net/keys/test-key",
        "tags": {
          "KMS": "SDKMS",
          "KeyType": "BYOK"
        }
      }
    ],
    "nextLink": null
  }
}
```

### Delete Key operation

This operation will delete a key in Fortanix Self-Defending KMS as well as Azure key vault.

#### Parameters

* `operation`: The operation which you want to perform. A valid value is `delete`.
* `key_name`: Name of the key
* `key_vault`: Azure key vault name
* `secret_id`: The response of `configuration` operation. 

Input JSON
```
{
  "operation": "delete",
  "key_name": "test-key",
  "key_vault": "test-hsm-keyvault",
  "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
}
```

Output JSON
```
{
  "result": {
    "scheduledPurgeDate": 1601363625,
    "tags": {
      "KMS": "SDKMS",
      "KeyType": "BYOK"
    },
    "deletedDate": 1593587625,
    "key": {
      "kid": "https://test-hsm-keyvault.vault.azure.net/keys/test-key/e71e5af81eaa4cbd85674d8b7a76d065",
      "n": "AL2b7tdZzZugFJI3mRS39h_6x9hh4XKJ3W3UrbwFtA9bZ7kEfGWIyE1IJWQX5KGkW26WkYiAABvx1bU4J7lO1TFkVjvHYRr5cC5eAySBGC1yaxrZ-3SguE7R33EF54ja3doeqapnkCM6GK2RuhIsT4Spz3cm9P0dfknz3DapON-7",
      "kty": "RSA",
      "e": "AQAB",
      "key_ops": [
        "encrypt",
        "decrypt",
        "sign",
        "verify",
        "wrapKey",
        "unwrapKey"
      ]
    },
    "attributes": {
      "enabled": true,
      "recoveryLevel": "Recoverable+Purgeable",
      "created": 1593587492,
      "updated": 1593587492
    },
    "recoveryId": "https://test-hsm-keyvault.vault.azure.net/deletedkeys/test-key"
  }
}
```

## References
- [Azure HSM BYOK](https://docs.microsoft.com/en-us/azure/key-vault/keys/hsm-protected-keys)

## Release Notes
 Initial release
