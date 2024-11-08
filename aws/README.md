# FORTANIX DATA SECURITY MANAGER AWS KMS BRING YOUR OWN KEY (BYOK) PLUGIN

> NOTE: This plugin should be considered deprecated and users are advised to migrate to the native functionality in DSM.

## Introduction
The cloud services provide many advantages but the major disadvantage of cloud providers has been security because
physically your data resides with the cloud provider. To keep data secure in a cloud provider environment, enterprises
use encryption. So securing their encryption keys become significantly important. Bring Your Own Key (BYOK) allows
enterprises to encrypt their data and retain control and management of their encryption keys. This plugin provides an
implementation to use the AWS cloud BYOK model.

## Requirement
- Fortanix Data Security Manager Version >= 3.17.1330

## Use cases
The plugin can be used to

- Push Fortanix Data Security Manager key in AWS KMS
- List Fortanix Data Security Manager AWS BYOK key
- Rotate Fortanix Data Security Manager AWS BYOK key
- Disable AWS BYOK key from Fortanix Data Security Manager
- Enable AWS BYOK key from Fortanix Data Security Manager
- Delete AWS BYOK key from Fortanix Data Security Manager
- Reimport key material from Fortanix Data Security Manager to AWS CMK


## Setup
- Log in to AWS portal
- Create AWS IAM policy
- Create AWS KMS policy
- Attach policy to IAM user
- Alternatively, setup AssumeRole or AssumeRoleWithSAML

## Input/Output JSON object format

### Configure operation
This operation configures AWS IAM secret key and access key in Fortanix Data Security Manager and returns a UUID. You need
to pass this UUID for other operations. This is a one time process.

#### Parameters

* `operation`: The operation which you want to perform. A valid value is `configure`.
* `secret_key`: AWS secret key
* `access_key`: AWS access key

#### Example
Input JSON
```
{
  "operation": "configure",
  "secret_key": "GZA....sz",
  "access_key": "AK...ZCX"
}
```
Output JSON
```
{
  "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
}
```

### Configure SAML operation
This operation configures AWS IAM SAML Identity Provider (IdP) and an administrator or API credential in Fortanix
Data Security Manager and returns a UUID. You need to pass this UUID for other operations. This is a one time process.

#### Parameters
* `operation`: The operation which you want to perform. A valid value is `configure_saml`.
* `host`: SAML Identity Provider host
* `resource`: SAML Identity Provider API suffix
* `username`: SAML Identity Provider Admin or API credential
* `password`: SAML Identity Provider Admin or API credential

#### Example

Input JSON
```
{
  "operation": "configure_saml",
  "host"     : "dev-95xx74.okta.com",
  "resource" : "amazon_aws/exk19l...S04x7",
  "username" : "joe@fortanix.com",
  "password" : "s$O...x245"
}
```
Output JSON
```
{
  "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
}
```

### AssumeRole operation
This operation takes the configured IAM user access credential and a role ARN as input to assume a new target role for
the IAM user. It produces a temporary security credential valid for 15 mins.

#### Parameters
* `operation`: The operation which you want to perform. A valid value is `assumerole`.
* `secret_id`: The response of `configuration` operation.
* `role_arn`: AWS ARN for the target IAM role

#### Example

Input JSON
```
{
  "operation": "assumerole",
  "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224",
  "role_arn": "arn:aws:iam::123456789012:role/target-assume-role"
}
```
Output JSON
```
{
  "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
}
```

### AssumeRoleWithSAML operation
This operation takes the configured IAM IdP Principal ARN and and a role ARN as input to assume a new target role for
the external federated user. It produces a temporary security credential valid for 15 mins.

#### Parameters
* `operation`: The operation which you want to perform. A valid value is `assumerole`.
* `secret_id`: The response of `configuration` operation.
* `role_arn`: AWS ARN for the target IAM role
* `principal_arn`: AWS ARN for the preconfigured IAM IdP federating the external user

#### Example

Input JSON
```
{
  "operation": "assumerolewithsaml",
  "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
  "role_arn": "arn:aws:iam::763471887487:role/SAML-default-role",
  "principal_arn": "arn:aws:iam::763471887487:saml-provider/OKTA"
}
```
Output JSON
```
{
  "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
}
```

### Create operation
This operation will create an AES-256 key in Fortanix Data Security Manager and import it in AWS KMS.

#### Parameters
* `operation`: The operation which you want to perform. A valid value is `create`.
* `name`: Name of the key
* `secret_id`: The response of `configuration` or `assumerole` operation.

#### Example

Input JSON
```
{
  "operation": "create",
  "name": "test-key",
  "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
}
```

Output JSON
```
{
  "key_size": 256,
  "custom_metadata": {
    "AWS_KEY_ID": "46fa7bfd-24de-4e5d-be94-99fa3e3bf09e"
  },
  "created_at": "20200725T155625Z",
  "lastused_at": "19700101T000000Z",
  "obj_type": "AES",
  "never_exportable": false,
  "state": "Active",
  "acct_id": "15e5e446-c911-4ad4-92b4-85eabefabfe7",
  "activation_date": "20200725T155625Z",
  "creator": {
    "plugin": "c2aa3055-5532-4ff2-8ca5-cb450c26e280"
  },
  "key_ops": [
    "ENCRYPT",
    "DECRYPT",
    "EXPORT",
    "APPMANAGEABLE"
  ],
  "enabled": true,
  "origin": "FortanixHSM",
  "kid": "04286b5c-4707-4ed1-bf92-934c7a077d5f",
  "name": "test-key",
  "public_only": false,
  "group_id": "9564adfd-2399-46d0-90c0-4cf80b7bcc33",
  "compliant_with_policies": true
}
```

### List operation
This operation will list all the BYOK keys from AWS.

#### Parameters
* `operation`: The operation which you want to perform. A valid value is `list`.
* `secret_id`: The response of `configuration` or `assumerole` operation.

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
  "KeyCount":1,
  "Keys":[
    {
      "KeyArn":"arn:aws:kms:us-west-1:513076507034:key/46fa7bfd-24de-4e5d-be94-99fa3e3bf09e",
      "KeyId":"46fa7bfd-24de-4e5d-be94-99fa3e3bf09e
    }
  ],
  "Truncated":false
}
```

### Rotate operation
This operation will rotate a key in Fortanix Data Security Manager as well as in AWS KMS key.

#### Parameters
* `operation`: The operation which you want to perform. A valid value is `rotate`.
* `name`: Name of the key
* `secret_id`: The response of `configuration` or `assumerole` operation.

#### Example

Input JSON
```
{
  "operation": "rotate",
  "name": "test-key",
  "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
}
```

Output JSON
```
{
  "obj_type": "AES",
  "kid": "49521024-e28f-4f6c-82e7-a9f29088ec43",
  "activation_date": "20200725T155809Z",
  "lastused_at": "19700101T000000Z",
  "compliant_with_policies": true,
  "group_id": "9564adfd-2399-46d0-90c0-4cf80b7bcc33",
  "enabled": true,
  "acct_id": "15e5e446-c911-4ad4-92b4-85eabefabfe7",
  "key_ops": [
    "ENCRYPT",
    "DECRYPT",
    "EXPORT",
    "APPMANAGEABLE"
  ],
  "origin": "FortanixHSM",
  "created_at": "20200725T155809Z",
  "key_size": 256,
  "state": "Active",
  "creator": {
    "plugin": "c2aa3055-5532-4ff2-8ca5-cb450c26e280"
  },
  "never_exportable": false,
  "custom_metadata": {
    "AWS_KEY_ID": "129bfa49-3dde-4d5f-87f7-f883e80e7893"
  },
  "name": "test-key",
  "public_only": false
}
```

### Disable operation
This operation will disable a AWS KMS key.

#### Parameters
* `operation`: The operation which you want to perform. A valid value is `disable`.
* `name`: Name of the key
* `secret_id`: The response of `configuration` operation.

#### Example
Input JSON
```
{
  "operation": "disable",
  "name": "test-key",
  "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
}
```

Output JSON
```
{}
```

### Enable operation
This operation will enable a AWS KMS disabled key.

#### Parameters
* `operation`: The operation which you want to perform. A valid value is `enable`.
* `name`: Name of the key
* `secret_id`: The response of `configuration` operation.

#### Example
Input JSON
```
{
  "operation": "enable",
  "name": "test-key",
  "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
}
```

Output JSON
```
{}
```

### Delete operation
This operation will schedule a AWS key deletion. This will not delete key from Fortanix Data Security Manager.

#### Parameters
* `operation`: The operation which you want to perform. A valid value is `delete`.
* `name`: Name of the key
* `secret_id`: The response of `configuration` operation.

#### Example
Input JSON
```
{
  "operation": "delete",
  "name": "test-key",
  "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
}
```

Output JSON
```
{}
```

### Cancel Delete operation
This operation will cancel a scheduled deletion of a AWS key deletion.

#### Parameters
* `operation`: The operation which you want to perform. A valid value is `cancel_deletion`.
* `name`: Name of the key
* `secret_id`: The response of `configuration` operation.

#### Example

Input JSON
```
{
  "operation": "cancel_deletion",
  "name": "test-key",
  "secret_id": "d6807129-27fe-4f64-8509-f9d3326c1de5"
}
```

Output JSON
```
{}
```

### Reimport operation
This operation will reimport the same key in an existing AWS KMS CMK.

#### Parameters
* `operation`: The operation which you want to perform. A valid value is `reimport`.
* `name`: Name of the key
* `secret_id`: The response of `configuration` operation.

#### Example
Input JSON
```
{
  "operation": "reimport",
  "name": "test-key",
  "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
}
```

Output JSON
```
{}
```
