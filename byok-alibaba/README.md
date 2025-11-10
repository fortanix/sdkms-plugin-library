# FORTANIX DSM ALIBABA CLOUD KMS BYOK PLUGIN

## Introduction

The Alibaba Cloud KMS BYOK plugin allows you to leverage Fortanix Data Security Manager (DSM) as a secure key source for Alibaba Cloud Key Management Service (KMS). This plugin enables you to generate, manage, and import cryptographic keys from DSM into Alibaba Cloud KMS while maintaining full control over your key material.

## Requirements

- Fortanix Data Security Manager account with plugin execution privileges
- Alibaba Cloud account with KMS service access
- Valid Alibaba Cloud Access Key ID and Access Key Secret with the following permissions:
  - `kms:CreateKey`
  - `kms:ImportKeyMaterial`
  - `kms:GetParametersForImport`
  - `kms:ListKeys`
  - `kms:DescribeKey`
  - `kms:EnableKey`
  - `kms:DisableKey`
  - `kms:ScheduleKeyDeletion`
  - `kms:CancelKeyDeletion`
  - `kms:DeleteKeyMaterial`

## Use Cases

The Alibaba Cloud KMS BYOK plugin can be used to address the following use cases:

- **Regulatory Compliance**: Meet compliance requirements by maintaining control over key generation and storage
- **Key Lifecycle Management**: Centrally manage key lifecycle while enabling cloud service encryption
- **Zero-Trust Architecture**: Ensure cryptographic keys are generated in certified hardware security modules
- **Kill Switch Capability**: Immediately disable cloud resources by deleting key material from Alibaba Cloud

## Setup

### 1. Deploy the Plugin

Deploy the Alibaba Cloud KMS BYOK plugin to your Fortanix DSM environment.

### 2. Configure Alibaba Cloud Credentials

Use the `configure` operation to securely store your Alibaba Cloud credentials in DSM.

## Input/Output JSON Object Format

### Configure

Stores Alibaba Cloud credentials securely in DSM for use by other operations.

**Parameters:**
- `access_key_id` (required): Your Alibaba Cloud Access Key ID
- `access_key_secret` (required): Your Alibaba Cloud Access Key Secret  
- `region` (required): Alibaba Cloud region (e.g., "us-east-1", "ap-southeast-1")

**Input JSON Object:**
```json
{
  "operation": "configure",
  "access_key_id": "LTAI4GBtY0*************",
  "access_key_secret": "your-access-key-secret",
  "region": "us-east-1"
}
```

**Output JSON Object:**
```json
{
  "secret_id": "b8a4d293-xxxx-xxxx-xxxx-def012345678"
}
```

### Create

Generates a new AES-256 key in DSM and creates a corresponding Customer Master Key (CMK) in Alibaba Cloud KMS with the DSM key material imported.

**Parameters:**
- `secret_id` (required): Secret ID returned from the configure operation
- `key_name` (required): Name for the key in DSM
- `key_spec` (optional): Key specification, defaults to "Aliyun_AES_256"
- `description` (optional): Description for the CMK in Alibaba Cloud
- `dkms_instance_id` (optional): Dedicated KMS instance ID for Software KMS

**Input JSON Object:**
```json
{
  "operation": "create",
  "secret_id": "b8a4d293-xxxx-xxxx-xxxx-def012345678",
  "key_name": "my-byok-key",
  "key_spec": "Aliyun_AES_256",
  "description": "My BYOK key for sensitive data encryption",
  "dkms_instance_id": "kst-phpt5t2de4gs3"
}
```

**Output JSON Object:**
```json
{
  "kid": "a1b2c3d4-xxxx-xxxx-xxxx-1234567890ab",
  "name": "my-byok-key",
  "custom_metadata": {
    "ALIBABA_KEY_ID": "key-php68cc......21c8h",
    "ALIBABA_REGION": "us-east-1"
  },
  "effective_key_policy": {
    "key_ops": [
      "ENCRYPT",
      "DECRYPT",
      "EXPORT",
      "APPMANAGEABLE"
    ]
  },
  "obj_type": "AES", 
  "key_size": 256,
  "creator": {
    "plugin": "0e73ea35-e982-4873-b72b-9e698219a2c1"
  },
  "key_creation_method": {
    "method": "Generate"
  }
}
```

### List

Lists all CMKs in the specified Alibaba Cloud region.

**Parameters:**
- `secret_id` (required): Secret ID returned from the configure operation

**Input JSON Object:**
```json
{
  "operation": "list",
  "secret_id": "b8a4d293-xxxx-xxxx-xxxx-def012345678"
}
```

**Output JSON Object:**
```json
{
  "Keys": {
    "key": [
      {
        "KeyArn": "acs:kms:us-east-1:506675....86468:key/key-php68cb47.....15yg",
        "KeyId": "key-php68cb47.....15yg"
      }
    ]
  },  
  "PageNumber": 1,
  "PageSize": 20,
  "TotalCount": 1,
  "RequestId": "3d4023ab-xxxx-xxxx-xxxx-abbab511386f"
}
```

### Enable

Enables a previously disabled CMK in Alibaba Cloud.

**Parameters:**
- `secret_id` (required): Secret ID returned from the configure operation
- `key_name` (required): Name of the DSM key

**Input JSON Object:**
```json
{
  "operation": "enable",
  "secret_id": "b8a4d293-xxxx-xxxx-xxxx-def012345678",
  "key_name": "my-byok-key"
}
```

**Output JSON Object:**
```json
{
  "RequestId": "60f32aca-xxxx-xxxx-xxxx-9ed108b23f02"
}
```

### Disable

Disables a CMK in Alibaba Cloud, making it unusable for cryptographic operations.

**Parameters:**
- `secret_id` (required): Secret ID returned from the configure operation
- `key_name` (required): Name of the DSM key

**Input JSON Object:**
```json
{
  "operation": "disable",
  "secret_id": "b8a4d293-1234-5678-9abc-def012345678",
  "key_name": "my-byok-key"
}
```

**Output JSON Object:**
```json
{
  "RequestId": "60f32aca-xxxx-xxxx-xxxx-9ed108b23f02"
}
```

### Delete

Schedules a CMK for deletion in Alibaba Cloud. The key will be permanently deleted after the specified pending window.

**Parameters:**
- `secret_id` (required): Secret ID returned from the configure operation
- `key_name` (required): Name of the DSM key
- `retention_period` (optional): Number of days before deletion (7-366), defaults to 366

**Input JSON Object:**
```json
{
  "operation": "delete",
  "secret_id": "b8a4d293-1234-5678-9abc-def012345678",
  "key_name": "my-byok-key",
  "retention_period": 366
}
```

**Output JSON Object:**
```json
{
  "RequestId": "60f32aca-xxxx-xxxx-xxxx-9ed108b23f02"
}
```

### Delete Key Material

Immediately removes the key material from Alibaba Cloud CMK, effectively disabling it as a "kill switch" while preserving the CMK metadata.

**Parameters:**
- `secret_id` (required): Secret ID returned from the configure operation
- `key_name` (required): Name of the DSM key

**Input JSON Object:**
```json
{
  "operation": "delete_key_material",
  "secret_id": "b8a4d293-xxxx-xxxx-xxxx-def012345678",
  "key_name": "my-byok-key"
}
```

**Output JSON Object:**
```json
{
  "KeyVersionId": "key-php68cc4f.....thhw09n7",
  "KeyId": "key-php68cc4......mv0qf",
  "RequestId": "9382c0be-xxxx-xxxx-xxxx-a8c2fc807bb2"
}
```

### Import to Existing

Imports new key material to an existing CMK shell in Alibaba Cloud.
Use option 'Create Key' in Alibaba Cloud KMS with below parameters to create the CMK shell and copy the Key ID.
- `Key Type`: Symmetric Key
- `Key Specifications`: Aliyun_AES_256
- `Key Usage`: ENCRYPT/DECRYPT
- `Key Alias`: Suitable_alias_name
- `Key Material Origin`: External (Import Key Material)

**Parameters:**
- `secret_id` (required): Secret ID returned from the configure operation
- `key_name` (required): Name for the new DSM key
- `alibaba_key_id` (required): Existing Alibaba Cloud CMK ID
- `key_spec` (optional): Key specification, defaults to "Aliyun_AES_256"

**Input JSON Object:**
```json
{
  "operation": "import_to_existing",
  "secret_id": "b8a4d293-1234-5678-9abc-def012345678",
  "key_name": "my-imported-key",
  "alibaba_key_id": "key-php68cc.....ls21c8h",
  "key_spec": "Aliyun_AES_256"
}
```

**Output JSON Object:**
```json
{
  "kid": "a1b2c3d4-xxxx-xxxx-xxxx-1234567890ab",
  "name": "my-byok-key",
  "custom_metadata": {
    "ALIBABA_KEY_ID": "key-php68c......ls21c8h",
    "ALIBABA_REGION": "us-east-1"
  },
  "effective_key_policy": {
    "key_ops": [
      "ENCRYPT",
      "DECRYPT",
      "EXPORT",
      "APPMANAGEABLE"
    ]
  },
  "obj_type": "AES", 
  "key_size": 256,
  "creator": {
    "plugin": "0e73ea35-xxxx-xxxx-xxxx-9e698219a2c1"
  },
  "key_creation_method": {
    "method": "Generate"
  }
}
```