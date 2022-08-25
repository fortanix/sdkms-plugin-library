# FORTANIX DSM Oracle Cloud Vault BRING YOUR OWN KEY (BYOK) PLUGIN

## Introduction

The cloud services provide many advantages but the major disadvantage of cloud providers has been security because physically your data resides with the cloud provider. To keep data secure in a cloud provider environment, enterprises use encryption. So securing their encryption keys become significantly important. Bring Your Own Key (BYOK) allows enterprises to encrypt their data and retain control and management of their encryption keys. This plugin provides an implementation to use the Oracle cloud BYOK model.

## Requirenment

- Fortanix DSM Version >= 4.6.2045

## Use cases

The plugin can be used to

- List Vaults
- List Keys in a Vault
- Get information about a key or key version from a Vault
- Enable or disable a key in a Vault
- Schedule the deletion or cancel the scheduled deletion of a key or key version in a Vault
- Import a Fortanix DSM Key into a Vault
- Rotate the Fortanix DSM Key and import the new key version into the Vault

## Setup

- Log in to Oracle Cloud portal
- In the user profile of the Oracle Cloud dashboard, create a new API Key
- Enable user in the Oracle Cloud with permissions to operate on one or more Vaults

## Input/Output JSON object format

### Configure operation

This operation configures Oracle Cloud API Key in Fortanix DSM and returns a UUID. This is a one time process.
You need to send this UUID for other operations. 

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `configure`.
* `secret_key`: Oracle Cloud API key containing either the base64 encoded private key or PKCS8 formatted.
               It can also be a named reference to an existing RSA private key in Fortanix DSM.
* `fingerprint`: MD5 hash of the private key specified in the `secret_key`.
* `region`: Default region the API Key has access to within Oracle Cloud.
* `ocids`: JSON structure consisting of the Oracle Cloud Tenant, User, and optionally the Compartment IDs.

#### Example

Input JSON
```
{
  "operation": "configure",
  "secret_key": "MIIEpAIBA...FOJ2xCw==",
  "fingerprint": "a9:d2:4f:fd:cc:10:...",
  "region": "us-phoenix-1",
  "ocids": {
    "tenant": "ocid1.tenancy.oc1..aaaaaaaaeipivgd4...",
    "user": "ocid1.user.oc1..aaaaaaaavcjkzwa7ipydz...",
    "compartment": "ocid1.tenancy.oc1..aaaaaaaaeipivgd43..."
  }
}
```
Output JSON
```
{
  "secret_id": "988d97f4-d1a7-4300-858e-76bbbcdf792a"
}
```

### Check operation

This operation will list Oracle Cloud Vaults

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `check`.
* `secret_id`: The response of `configuration` operation. 
* `compartment`: Optional. If specified, it will be used instead of the one
        configured previously for the query.

#### Example

Input JSON

```
{
  "operation": "check",
  "secret_id": "988d97f4-d1a7-4300-858e-76bbbcdf792a",
  "compartment": "ocid1.compartment.oc1..aaaaaaaag6kmml..."
}
```

Output JSON
```
[
  {
    "id": "ocid1.vault.oc1.phx.bzrgvxubaadcw.abyhqljr7xga42..."
    "replicaDetails": null,
    "isPrimary": true,
    "wrappingkeyId": "",
    "freeformTags": {
      "FX_PURPOSE": "engineering-plugin",
      "FX_USER": "daervveilnodp"
    },
    "cryptoEndpoint": "https://bzrgvxubaadcw-crypto.kms.us-phoenix-1.oraclecloud.com",
    "compartmentId": "ocid1.compartment.oc1..aaaaaaaag6kmml..."
    "vaultType": "DEFAULT",
    "lifecycleState": "ACTIVE",
    "displayName": "byoktest",
    "definedTags": {},
    "timeCreated": "2022-04-28T18:35:45.723Z",
    "restoredFromVaultId": null,
    "externalVendorMetadata": null,
    "managementEndpoint": "https://bzrgvxubaadcw-management.kms.us-phoenix-1.oraclecloud.com",
    "timeOfDeletion": null
  }
]
```

### Import operation

This operation will create an AES key in Fortanix DSM and import it into an Oracle Cloud Vault.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `import`.
* `secret_id`: The response of `configuration` operation. 
* `vault`: Prefix of the Vault endpoint obtained from the `check` operation.
* `name`: Name of the key to be exported from Fortanix DSM.
* `type`: AES is supported as of now. RSA is not yet and ECDSA is not supported.
* `size`: 128, 192, or 256 in bit length.
* `protection`: Valid values are `SOFTWARE` or `HSM`.
* `free_tags`: arbitrary key-value pairs expressed in JSON.

#### Example

Input JSON

```
{
  "operation": "import",
  "secret_id": "988d97f4-d1a7-4300-858e-76bbbcdf792a",
  "vault": "bzrgvxubaadcw",
  "name": "dsm_oci_key1",
  "type": "AES",
  "size": 256,
  "protection": "SOFTWARE",
  "free_tags": {"ftnxtag": "dsm"}
}
```

Output JSON
```
{
  "displayName": "dsm_oci_key1",
  "currentKeyVersion": "ocid1.keyversion.oc1.phx.bzrgvxubaadcw.aememj56wyiaa.abyhqljst4...",
  "externalKeyReference": null,
  "timeOfDeletion": null,
  "autoKeyRotationSchedule": null,
  "compartmentId": "ocid1.compartment.oc1..aaaaaaaag6kmmlk...",
  "timeCreated": "2022-05-11T16:59:13.756Z",
  "keyShape": {
    "algorithm": "AES",
    "length": 16,
    "curveId": null
  },
  "definedTags": {},
  "vaultId": "ocid1.vault.oc1.phx.bzrgvxubaadcw.abyhqljr7xg...",
  "lifecycleState": "CREATING",
  "id": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljsie...",
  "protectionMode": "SOFTWARE",
  "restoredFromKeyId": null,
  "autoKeyRotationStatus": null,
  "freeformTags": {
    "ftnxtag": "dsm"
  },
  "isPrimary": true,
  "replicaDetails": null
}
```

### List operation

This operation will list all the keys from an Oracle Cloud Vault.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `list`.
* `secret_id`: The response of `configuration` operation. 
* `vault`: Prefix of the Vault endpoint obtained from the `check` operation.

#### Example

Input JSON
```
{
  "operation": "list",
  "secret_id": "988d97f4-d1a7-4300-858e-76bbbcdf792a",
  "vault": "bzrgvxubaadcw"
}
```

Output JSON
```
[
  {
    "protectionMode": "SOFTWARE",
    "definedTags": {},
    "id": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljslgbob...",
    "lifecycleState": "ENABLED",
    "algorithm": "AES",
    "freeformTags": {
      "ftnxtag": "dsm"
    },
    "displayName": "dsm_oci_key1",
    "timeCreated": "2022-05-11T15:22:16.334Z",
    "compartmentId": "ocid1.compartment.oc1..aaaaaaaag6kmmlk...",
    "vaultId": "ocid1.vault.oc1.phx.bzrgvxubaadcw.abyhqljr7x..."
  },
  {
    "compartmentId": "ocid1.compartment.oc1..aaaaaaaag6kmmlk...",
    "id": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljr5h6pykvyh...",
    "vaultId": "ocid1.vault.oc1.phx.bzrgvxubaadcw.abyhqljr7x...",
    "lifecycleState": "ENABLED",
    "algorithm": "AES",
    "timeCreated": "2022-05-11T15:23:59.576Z",
    "freeformTags": {
      "ftnxtag": "dsm"
    },
    "definedTags": {},
    "protectionMode": "HSM",
    "displayName": "dsm_oci_key2"
 }
]
```

### Get operation

This operation will retrieve a specific key from an Oracle Cloud Vault.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `get`.
* `secret_id`: The response of `configuration` operation. 
* `vault`: Prefix of the Vault endpoint obtained from the `check` operation.
* `name`: Name of the key

#### Example

Input JSON
```
{
  "operation": "get | enable | disable",
  "secret_id": "988d97f4-d1a7-4300-858e-76bbbcdf792a",
  "vault": "bzrgvxubaadcw",
  "key": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljtay66z3uj4q..."
}
```

Output JSON
```
{
  "freeformTags": {
    "ftnxtag": "dsm"
  },
  "autoKeyRotationSchedule": null,
  "isPrimary": true,
  "timeCreated": "2022-05-11T15:22:16.334Z",
  "externalKeyReference": null,
  "keyShape": {
    "length": 16,
    "curveId": null,
    "algorithm": "AES"
  },
  "id": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljslgbob...",
  "timeOfDeletion": null,
  "protectionMode": "SOFTWARE",
  "lifecycleState": "ENABLED",
  "definedTags": {},
  "displayName": "dsm_oci_key1",
  "autoKeyRotationStatus": null,
  "currentKeyVersion": "ocid1.keyversion.oc1.phx.bzrgvxubaadcw.aememj55jkaaa.abyhqljsipc...",
  "replicaDetails": null,
  "vaultId": "ocid1.vault.oc1.phx.bzrgvxubaadcw.abyhqljr7...",
  "compartmentId": "ocid1.compartment.oc1..aaaaaaaag6kmmlk...",
  "restoredFromKeyId": null
}
```

### Disable operation

This operation will disable a key in an Oracle Cloud Vault.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `disable`.
* `secret_id`: The response of `configuration` operation. 
* `vault`: Prefix of the Vault endpoint obtained from the `check` operation.
* `name`: Name of the key  

#### Example

Input JSON
```
{
  "operation": "disable",
  "secret_id": "988d97f4-d1a7-4300-858e-76bbbcdf792a",
  "vault": "bzrgvxubaadcw",
  "key": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljslgbob..."
}
```

Output JSON
```
{
  "isPrimary": true,
  "id": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljslgbob...",
  "replicaDetails": null,
  "protectionMode": "SOFTWARE",
  "definedTags": {},
  "externalKeyReference": null,
  "lifecycleState": "DISABLING",
  "restoredFromKeyId": null,
  "autoKeyRotationSchedule": null,
  "compartmentId": "ocid1.compartment.oc1..aaaaaaaag6kmmlk...",
  "currentKeyVersion": "ocid1.keyversion.oc1.phx.bzrgvxubaadcw.aememj55jkaaa.abyhqljsipc2...",
  "timeOfDeletion": null,
  "vaultId": "ocid1.vault.oc1.phx.bzrgvxubaadcw.abyhqljr7...",
  "timeCreated": "2022-05-11T15:22:16.334Z",
  "displayName": "dsm_oci_key1",
  "freeformTags": {
    "ftnxtag": "dsm"
  },
  "keyShape": {
    "curveId": null,
    "length": 16,
    "algorithm": "AES"
  },
  "autoKeyRotationStatus": null
}
```

### Enable operation

This operation will enable a key in an Oracle Cloud Vault that was disabled.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `enable`.
* `secret_id`: The response of `configuration` operation. 
* `vault`: Prefix of the Vault endpoint obtained from the `check` operation.
* `name`: Name of the key  

#### Example

Input JSON
```
{
  "operation": "enable",
  "secret_id": "988d97f4-d1a7-4300-858e-76bbbcdf792a",
  "vault": "bzrgvxubaadcw",
  "key": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljslgbob7cn4vy6u7yzmqlryzsz4lbmjs5b5qrel6r2ymwkdekopkwq"
}
```

Output JSON
```
{
  "isPrimary": true,
  "id": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljslgbob...",
  "replicaDetails": null,
  "protectionMode": "SOFTWARE",
  "definedTags": {},
  "externalKeyReference": null,
  "lifecycleState": "ENABLING",
  "restoredFromKeyId": null,
  "autoKeyRotationSchedule": null,
  "compartmentId": "ocid1.compartment.oc1..aaaaaaaag6kmmlk...",
  "currentKeyVersion": "ocid1.keyversion.oc1.phx.bzrgvxubaadcw.aememj55jkaaa.abyhqljsipc2...",
  "timeOfDeletion": null,
  "vaultId": "ocid1.vault.oc1.phx.bzrgvxubaadcw.abyhqljr7...",
  "timeCreated": "2022-05-11T15:22:16.334Z",
  "displayName": "dsm_oci_key1",
  "freeformTags": {
    "ftnxtag": "dsm"
  },
  "keyShape": {
    "curveId": null,
    "length": 16,
    "algorithm": "AES"
  },
  "autoKeyRotationStatus": null
}
```

### Delete operation

This operation will schedule a key deletion in an Oracle Cloud Vault.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `enable`.
* `secret_id`: The response of `configuration` operation. 
* `vault`: Prefix of the Vault endpoint obtained from the `check` operation.
* `key`: Oracle Cloud ID of the key.
* `expiry`: Number of days to schedule the deletion. Specify between 7, and 30.

#### Example

Input JSON
```
{
  "operation": "delete",
  "secret_id": "988d97f4-d1a7-4300-858e-76bbbcdf792a",
  "vault": "bzrgvxubaadcw",
  "key": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljr5h6p...",
  "expiry ": "21"
}
```

Output JSON
```
{
  "autoKeyRotationStatus": null,
  "keyShape": {
    "curveId": null,
    "length": 32,
    "algorithm": "AES"
  },
  "autoKeyRotationSchedule": null,
  "definedTags": {},
  "replicaDetails": null,
  "protectionMode": "SOFTWARE",
  "displayName": "dsm_oci_key2",
  "currentKeyVersion": "ocid1.keyversion.oc1.phx.bzrgvxubaadcw.aeydmj55zhqaa.abyhqljtfdqe...",
  "externalKeyReference": null,
  "compartmentId": "ocid1.compartment.oc1..aaaaaaaag6kmmlk...",
  "vaultId": "ocid1.vault.oc1.phx.bzrgvxubaadcw.abyhqljr7xga423...",
  "freeformTags": {
    "ftnxtag": "dsm"
  },
  "restoredFromKeyId": null,
  "timeCreated": "2022-05-11T15:23:59.576Z",
  "timeOfDeletion": "2022-05-18T17:47:45.000Z",
  "lifecycleState": "SCHEDULING_DELETION",
  "id": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljr5h6p...",
  "isPrimary": true
}
```

### Undelete operation

This operation will cancel the scheduled key deletion in an Oracle Cloud Vault.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `enable`.
* `secret_id`: The response of `configuration` operation. 
* `vault`: Prefix of the Vault endpoint obtained from the `check` operation.
* `key`: Oracle Cloud ID of the key.

#### Example

Input JSON
```
{
  "operation": "undelete",
  "secret_id": "988d97f4-d1a7-4300-858e-76bbbcdf792a",
  "vault": "bzrgvxubaadcw",
  "key": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljr5h6p..."
}
```

Output JSON
```
{
  "protectionMode": "SOFTWARE",
  "id": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljr5h6p...",
  "timeOfDeletion": "2022-05-18T17:47:45.000Z",
  "isPrimary": true,
  "lifecycleState": "CANCELLING_DELETION",
  "keyShape": {
    "length": 32,
    "algorithm": "AES",
    "curveId": null
  },
  "restoredFromKeyId": null,
  "externalKeyReference": null,
  "currentKeyVersion": "ocid1.keyversion.oc1.phx.bzrgvxubaadcw.aeydmj55zhqaa.abyhqljtfdqe...",
  "autoKeyRotationSchedule": null,
  "replicaDetails": null,
  "timeCreated": "2022-05-11T15:23:59.576Z",
  "displayName": "dsm_oci_key2",
  "autoKeyRotationStatus": null,
  "compartmentId": "ocid1.compartment.oc1..aaaaaaaag6kmmlk...",
  "vaultId": "ocid1.vault.oc1.phx.bzrgvxubaadcw.abyhqljr7xga423...",
  "definedTags": {},
  "freeformTags": {
    "ftnxtag": "dsm"
  }
}
```

### GetVersions operation

This operation will list key version in an Oracle Cloud Vault.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `enable`.
* `secret_id`: The response of `configuration` operation. 
* `vault`: Prefix of the Vault endpoint obtained from the `check` operation.
* `key`: Oracle Cloud ID of the key to list versions for.

#### Example

Input JSON
```
{
  "operation": "getversions",
  "secret_id": "988d97f4-d1a7-4300-858e-76bbbcdf792a",
  "vault": "bzrgvxubaadcw",
  "key": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljrwxn4..."
}
```

Output JSON
```
[
  {
    "vaultId": "ocid1.vault.oc1.phx.bzrgvxubaadcw.abyhqljr7xga4...",
    "lifecycleState": "PENDING_DELETION",
    "id": "ocid1.keyversion.oc1.phx.bzrgvxubaadcw.aeebmj554diaa.abyhqljrakwdql4...",
    "timeCreated": "2022-05-11T16:02:22.066Z",
    "origin": "EXTERNAL",
    "compartmentId": "ocid1.compartment.oc1..aaaaaaaag6kmmlkj...",
    "timeOfDeletion": "2022-05-18T16:21:05.000Z",
    "keyId": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljrwxn4..."
  },
  {
    "timeOfDeletion": "2022-05-18T16:21:05.000Z",
    "origin": "EXTERNAL",
    "compartmentId": "ocid1.compartment.oc1..aaaaaaaag6kmmlk...",
    "vaultId": "ocid1.vault.oc1.phx.bzrgvxubaadcw.abyhqljr7x...",
    "id": "ocid1.keyversion.oc1.phx.bzrgvxubaadcw.aeinmj553siaa.abyhqljrauadk...",
    "timeCreated": "2022-05-11T16:01:13.687Z",
    "keyId": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljrwxn4c...",
    "lifecycleState": "PENDING_DELETION"
  }
]
```

### Rotate operation

This operation will rotate a key in Fortanix DSM and import the rekeyed material
as a new key version in an Oracle Cloud Vault.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `rotate`.
* `secret_id`: The response of `configuration` operation. 
* `vault`: Prefix of the Vault endpoint obtained from the `check` operation.
* `key`: Oracle Cloud ID of the key.
* `name`: Name of the DSM key to rotate. Will create if not found.

#### Example

Input JSON
```
{
  "operation": "rotate",
  "secret_id": "988d97f4-d1a7-4300-858e-76bbbcdf792a",
  "vault": "bzrgvxubaadcw",
  "key": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljsie6v...",
  "name ": "dsm_oci_key4"
}
```

Output JSON
```
{
  "id": "ocid1.keyversion.oc1.phx.bzrgvxubaadcw.aememj573uyaa.abyhqljsun3dkw4rfji2mcvcdcikfck4ibm2yyyhzjsljshdcs7ke3z2wp3a",
  "vaultId": "ocid1.vault.oc1.phx.bzrgvxubaadcw.abyhqljr7xga423iq7q2ugk266uldexjdmzstpepbbuchhudk53pzkgzh35q",
  "origin": "EXTERNAL",
  "timeOfDeletion": null,
  "replicaDetails": {
    "replicationId": null
  },
  "restoredFromKeyVersionId": null,
  "lifecycleState": "CREATING",
  "compartmentId": "ocid1.compartment.oc1..aaaaaaaag6kmmlkj5cz6aqf37zlf5mi3boxkcp3iri2drazwcqtgssnyqwya",
  "keyId": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljsie6vrxncbjurjddtuuymtuclg3io3zxzng2rhnkgdpdhimxdcqdq",
  "isPrimary": true,
  "timeCreated": "2022-05-11T18:17:55.363Z",
  "publicKey": null
}
```

### Import Version operation

This operation will import an existing key from Fortanix DSM as a new key version in an Oracle Cloud Vault.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `importversion`.
* `secret_id`: The response of `configuration` operation. 
* `vault`: Prefix of the Vault endpoint obtained from the `check` operation.
* `key`: Oracle Cloud ID of the key.
* `name`: Name of the existing DSM key to import. Will create if not found.

#### Example

Input JSON
```
{
  "operation": "rotate",
  "secret_id": "988d97f4-d1a7-4300-858e-76bbbcdf792a",
  "vault": "bzrgvxubaadcw",
  "key": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljsie6v...",
  "name ": "dsm_oci_key4"
}
```

Output JSON
```
{
  "id": "ocid1.keyversion.oc1.phx.bzrgvxubaadcw.aememj573uyaa.abyhqljsun3dkw4rfji2mcvcdcikfck4ibm2yyyhzjsljshdcs7ke3z2wp3a",
  "vaultId": "ocid1.vault.oc1.phx.bzrgvxubaadcw.abyhqljr7xga423iq7q2ugk266uldexjdmzstpepbbuchhudk53pzkgzh35q",
  "origin": "EXTERNAL",
  "timeOfDeletion": null,
  "replicaDetails": {
    "replicationId": null
  },
  "restoredFromKeyVersionId": null,
  "lifecycleState": "CREATING",
  "compartmentId": "ocid1.compartment.oc1..aaaaaaaag6kmmlkj5cz6aqf37zlf5mi3boxkcp3iri2drazwcqtgssnyqwya",
  "keyId": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljsie6vrxncbjurjddtuuymtuclg3io3zxzng2rhnkgdpdhimxdcqdq",
  "isPrimary": true,
  "timeCreated": "2022-05-11T18:17:55.363Z",
  "publicKey": null
}
```

### Delete version operation

This operation will schedule a key version deletion in an Oracle Cloud Vault.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `enable`.
* `secret_id`: The response of `configuration` operation. 
* `vault`: Prefix of the Vault endpoint obtained from the `check` operation.
* `key`: Oracle Cloud ID of the key.
* `version`: Oracle Cloud ID of the key version.
* `expiry`: Number of days to schedule the deletion. Specify between 7, and 30.

#### Example

Inpua JSON
```
{
  "operation": "deleteversion",
  "secret_id": "988d97f4-d1a7-4300-858e-76bbbcdf792a",
  "vault": "bzrgvxubaadcw",
  "key": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljsie6vrx...",
  "version": "ocid1.keyversion.oc1.phx.bzrgvxubaadcw.aememj573uyaa.abyhqljsun3dkw...",
  "expiry ": 18
}
```

Output JSON
```
{
  "timeOfDeletion": "2022-05-29T18:19:52.000Z",
  "lifecycleState": "SCHEDULING_DELETION",
  "vaultId": "ocid1.vault.oc1.phx.bzrgvxubaadcw.abyhqljr7xga423...",
  "autoKeyRotationStatus": null,
  "definedTags": {},
  "displayName": "dsm_oci_key4",
  "timeCreated": "2022-05-11T16:59:13.756Z",
  "freeformTags": {
    "ftnxtag": "dsm"
  },
  "id": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljsie6vrx...",
  "currentKeyVersion": "ocid1.keyversion.oc1.phx.bzrgvxubaadcw.aememj573uyaa.abyhqljsun3dkw...",
  "keyShape": {
    "length": 16,
    "curveId": null,
    "algorithm": "AES"
  },
  "compartmentId": "ocid1.compartment.oc1..aaaaaaaag6kmmlkj5cz6...",
  "restoredFromKeyId": null,
  "protectionMode": "SOFTWARE",
  "isPrimary": true,
  "autoKeyRotationSchedule": null,
  "replicaDetails": null,
  "externalKeyReference": null
}
```

### Undelete version operation

This operation will cancel the scheduled key version deletion in an Oracle Cloud Vault.

#### Parameters 

* `operation`: The operation which you want to perform. A valid value is `enable`.
* `secret_id`: The response of `configuration` operation. 
* `vault`: Prefix of the Vault endpoint obtained from the `check` operation.
* `key`: Oracle Cloud ID of the key.
* `version`: Oracle Cloud ID of the key version.

#### Example

Input JSON
```
{
  "operation": "undeleteversion",
  "secret_id": "988d97f4-d1a7-4300-858e-76bbbcdf792a",
  "vault": "bzrgvxubaadcw",
  "key": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljsie6vrx...",
  "version": "ocid1.keyversion.oc1.phx.bzrgvxubaadcw.aememj573uyaa.abyhqljsun3dkw..."
}
```

Output JSON
```
{
  "externalKeyReference": null,
  "isPrimary": true,
  "id": "ocid1.key.oc1.phx.bzrgvxubaadcw.abyhqljsie6vrx...",
  "freeformTags": {
    "ftnxtag": "dsm"
  },
  "replicaDetails": null,
  "definedTags": {},
  "restoredFromKeyId": null,
  "compartmentId": "ocid1.compartment.oc1..aaaaaaaag6kmmlk...",
  "autoKeyRotationStatus": null,
  "timeOfDeletion": "2022-05-29T18:19:52.000Z",
  "keyShape": {
    "length": 16,
    "algorithm": "AES",
    "curveId": null
  },
  "autoKeyRotationSchedule": null,
  "protectionMode": "SOFTWARE",
  "vaultId": "ocid1.vault.oc1.phx.bzrgvxubaadcw.abyhqljr7xga423...",
  "displayName": "dsm_oci_key4",
  "currentKeyVersion": "ocid1.keyversion.oc1.phx.bzrgvxubaadcw.aememj573uyaa.abyhqljsun3dkw4r...",
  "timeCreated": "2022-05-11T16:59:13.756Z",
  "lifecycleState": "CANCELLING_DELETION"
}
```

## References

 * [Oracle Cloud REST API](https://docs.oracle.com/en-us/iaas/api/#/en/key/release/Vault/)
 * [Oracle Cloud API signature v1](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm)
