# Synchronize events between Fortanix DSM and AWS CloudTrail

This plugin can be used to syncrhonize events from AWS CloudTrail with DSM Audit log
for keys in DSM that were brought into AWS Cloud KMS (BYOK as part of Cloud-Data-Control.
The merged events can be uploaded to Amazon S3.

## Input Commands

The plugin accepts a JSON object as input with the following mandatory fields:

- `operation`: the operation to execute, see below for a list of operations,
- `secret_id`: a string identifying the DSM secret object containing the AWS IAM
    credentials. This is not required and instead output from the `configure` operation.

Some operations require more fields in the input as noted below.

The plugin accepts the following operations:

### Configure
- `configure`: generates a new secret with AWS IAM credentials it receives as input
  in a DSM security object named randomly.

  The input parameters are:
  - Access Key Id: String
  - Secret Access Key: String
  - Region: String; defaults to `us-west-1`
  - Session Token: (optional) String; obtained through AWS STS

  The output contains a JSON object with a key called `secret_id` that is the UUID of the 
  DSM secret and will be used in all subsequent operations.
  The AWS IAM access key needs to have permission to read CloudTrail events and also write
  to an Amazon S3 bucket.

### List DSM Keys
- `list-dsm-keys`: fetches all AWS Cloud KMS relevant keys from Fortanix DSM groups
  the plugin is a member of.

  The input parameters are:
  - Key: (optional) String; to filter by key name or UUID in Fortanix DSM

  The output contains a JSON object array of keys that were copied to AWS Cloud KMS using 
  Fortanix Cloud Data Control, found across groups within Fortanix DSM that the plugin is 
  a member of.
  More information regarding Cloud Data Control keys is available at [Fortanix DSM with External AWS Cloud KMS](https://support.fortanix.com/hc/en-us/articles/360055605471-User-s-Guide-AWS-External-KMS)

### List DSM Events
- `list-dsm-events`: fetches all events from Fortanix DSM relevant to the AWS Cloud KMS copied
  keys, or events pertaining any specific keys, as per input.

  The input parameters are:
  - Key: (optional) String; to filter by key name or UUID in Fortanix DSM

  The output contains a JSON object array of events in Fortanix DSM corresponding to keys
  that were copied to AWS Cloud KMS using Fortanix Cloud Data Control, found across groups
  within Fortanix DSM that the plugin is a member of.

### List AWS Keys
- `list-aws-keys`: fetches all keys from AWS Cloud KMS accessible to the AWS IAM credential.

  The input parameters are:
  - Secret ID: UUID of the Fortanix DSM Security Object obtained from `configure` operation.

  The output contains a JSON object array containing of keys found in AWS Cloud KMS. The region will
  correspond to that specified during the `configure` operation.

### List AWS Events
- `list-aws-events`: fetches all events from AWS CloudTrail, if no filters are specified.
  More information regarding filters is available at [AWS CloudTrail LookupEvents documentation](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.htm)

  The input parameters are:
  - Secret ID: UUID of the Fortanix DSM Security Object obtained from `configure` operation.
  - Lookup Attribute Key: String or Array
  - Lookup Attribute Value: String or Array; if latter, sized as per the Lookup Attribute Key array.

### Merge Events
- `merge-events`: fetches all events from AWS CloudTrail, and merges with Audit log from Fortanix DSM.

  The input parameters are:
  - Secret ID: UUID of the Fortanix DSM Security Object obtained from `configure` operation.
  - Reverse Chronology: Boolean; defaults to `false`, unless set to `true`.

  The output contains a JSON object array containing of events in chronological (or reverse) across both
  AWS CloudTrail and Fortanix DSM for keys that are common across both systems.

### Upload Events
- `upload-events`: uploads a single file with output from Merge Events operation on to Amazon S3.

  The input parameters are:
  - Secret ID: UUID of the Fortanix DSM Security Object obtained from `configure` operation.
  - Bucket: String; name of the Amazon S3 bucket.
  - Object Key: String; name of the Amazon S3 bucket object key to create or update.

  The output contains a JSON object array containing of events in chronological (or reverse) across both
  AWS CloudTrail and Fortanix DSM for keys that are common across both systems.


## Example Usage

Invoke the plugin with the following input to check for AWS Cloud KMS keys in Fortanix DSM:
```
{
  "operation": "list-dsm-keys",
  "key": "55526741-7528-44d4-89de-9db3d1e93fc3"
}

```
If pertinent keys are found, the output will be (an array of or) a single Security Object(s) as follows:
```
[
  {
    "kid": "55526741-7528-44d4-89de-9db3d1e93fc3",
    "name": "Master-S3-Key-Service_Copy(copied at 15-03-2022 04:04:40.542)",
    "key_size": 256,
    "obj_type": "AES",
    "created_at": "20220315T200440Z",
    "lastused_at": "19700101T000000Z",
    "group_id": "04468c2b-ad54-4b3a-ba0b-6ad67b0a6bc1",
    "enabled": true,
    "description": "",
    "never_exportable": false,
    "state": "Active",
    "activation_date": "20220315T200440Z",
    "acct_id": "cdab6346-3b68-40ed-9a00-9057ce723486",
    "origin": "FortanixHSM",
    "key_ops": [
      "APPMANAGEABLE"
    ],
    "public_only": false,
    "creator": {
      "user": "b3e23fe0-dabc-402d-a911-f109e0c96f68"
    },
    "custom_metadata": {
      "aws-aliases": "DSM-AES-source-key1\r\n",
      "aws-policy": "{\n\"Version\":\"2012-10-17\",\n\"Id\":\"key-default-1\",\n \"Statement\":[{\n\"Sid\":\"Enable IAM User Permissions\",\n\"Effect\":\"Allow\",\n\"Principal\":{\n\"AWS\":\"arn:aws:iam::123471887489:iamusr\"\n},\n    \"Action\":\"kms:*\",\n\"Resource\":\"*\"\n} ]\n}",
      "aws-key-state": "Enabled"
    },
    "external": {
      "hsm_group_id": "04468c2b-ad54-4b3a-ba0b-6ad67b0a6bc1",
      "id": {
        "key_arn": "arn:aws:kms:us-east-2:123471887489:key/94c76869-d14f-4ca9-9980-a88be78f8f7b",
        "key_id": "94c76869-d14f-4ca9-9980-a88be78f8f7b"
      }
    },
    "links": {
      "copiedFrom": "a70fe8fb-588a-446b-aa3c-2576ec647425"
    },
    "aes": {
      "key_sizes": null,
      "tag_length": null,
      "random_iv": null,
      "fpe": null,
      "iv_length": null,
      "cipher_mode": null
    },
    "compliant_with_policies": true
  }
]
```

Now that you have confirmed the presence of an AWS Cloud KMS key in the Fortanix DSM group that thsis Plugin
belongs to, you may invoke the plugin with the following input to initialize the cloud operations:
```
{
  "operation": "configure",
  "region": "us-east-2",
  "access_key": "AKRAVOI8NGDNB0426...",
  "secret_key": "Bt2rPIGp9aXt8h2y2..."
}
```

If successful, you'd see an output like this:
```
{
  "secret_id": "6c7cc3ec-1de6-4526-b272-1e3addd120b4"
}
```

You can copy the JSON output key and value or just the value to substitute in latter operations.
To check if the AWS IAM access key is valid and has sufficient permissions, run the `list-aws-events`
read-only operation using the `secret_id` input:

```
{
  "operation": "list-aws-events",
  "secret_id": "6c7cc3ec-1de6-4526-b272-1e3addd120b4"
}
```
The output should list all events from AWS CloudTrail, as there is no explicit lookup attribute
specified. However, for the `merge-events` operation, the Plugin will apply an implicit and pertinent KMS filter.

Alternatively, add an explicit filter as follows:
```
{
  "operation": "list-aws-events",
  "secret_id": "6c7cc3ec-1de6-4526-b272-1e3addd120b4",
  "lookup_attribkey": "EventSource",
  "lookup_attribval": "kms.amazonaws.com"
}
```

If the `secret_id` is correct you'd see an output like this:
```
[
  {
    "target": "arn:aws:kms:us-east-2:123471887489:key/94c76869-d14f-4ca9-9980-a88be78f8f7b",
    "who": "IAMUser <123471887489/sdkmsusr/AKIA3DQTYPR7TLMRXTCS>",
    "what": "EnableKey",
    "ts": 1647459645,
    "when": "2022-03-16T19:40:45Z"
  },
  {
    "what": "ListResourceTags",
    "when": "2022-03-15T21:17:16Z",
    "who": "IAMUser <123471887489/sdkmsusr/AKIA3DQTYPR7TLMRXTCS>",
    "target": "arn:aws:kms:us-east-2:123471887489:key/94c76869-d14f-4ca9-9980-a88be78f8f7b",
    "ts": 1647379036
  }
]
```

Another operation to help in troubleshooting is `list-aws-keys`, which should find relevant keys in
Fortanix DSM that were copied to AWS Cloud KMS and accessible through IAM access key configured earlier.

This operation only requires the `secret_id` parameter as follows:
```
{
  "operation": "list-aws-keys",
  "secret_id": "6c7cc3ec-1de6-4526-b272-1e3addd120b4"
}
```
If the `secret_id` is correct you'd see an output like this:
```
{
  "Keys": [
    {
      "KeyArn": "arn:aws:kms:us-east-2:123471887489:key/94c76869-d14f-4ca9-9980-a88be78f8f7b",
      "KeyId": "94c76869-d14f-4ca9-9980-a88be78f8f7b"
    },
    {
      "KeyArn": "arn:aws:kms:us-east-2:123471887489:key/bc9ba11e-8161-4d2d-b151-58aed08d140e",
      "KeyId": "bc9ba11e-8161-4d2d-b151-58aed08d140e"
    }
  ]
}
```

The main operations as per the objective of this plugin are `merge-events` and `upload-events`.
While `merge-events` only displays the output after synchronizing the events from AWS CloudTrail and
Fortanix DSM Audit history, the latter uploads the events to Amazon S3.
```
{
  "operation": "merge-events",
  "secret_id": "6c7cc3ec-1de6-4526-b272-1e3addd120b4",
  "revchrono": true
}
```
If the `secret_id` is correct you'd see an output like this:
```
[
  {
    "source": "fortanix-dsm",
    "who": "User <b3e23fe0-dabc-402d-a911-f109e0c96f68>",
    "when": "2022-03-16T19:44:21Z",
    "target": "ADMINISTRATIVE/55526741-7528-44d4-89de-9db3d1e93fc3",
    "ts": 1647459861,
    "what": "User \"anjunas@fortanix.com\" updated key \"Master-Key\". Changes: custom metadata updated"
  },
  {
    "ts": 1647459861,
    "source": "aws-cloudtrail",
    "when": "2022-03-16T19:44:21Z",
    "target": "arn:aws:kms:us-east-2:[123471887489:key/94c76869-d14f-4ca9-9980-a88be78f8f7b",
    "what": "EnableKey",
    "who": "IAMUser <[123471887489/sdkmsusr/AKIA3DQTYPR7TLMRXTCS>"
  },
  {
    "source": "fortanix-dsm",
    "who": "User <b3e23fe0-dabc-402d-a911-f109e0c96f68>",
    "when": "2022-03-16T19:40:45Z",
    "ts": 1647459645,
    "target": "ADMINISTRATIVE/55526741-7528-44d4-89de-9db3d1e93fc3",
    "what": "User \"anjunas@fortanix.com\" updated key \"Master-Key\". Changes: state enabled"
  },
  {
    "who": "IAMUser <[123471887489/sdkmsusr/AKIA3DQTYPR7TLMRXTCS>",
    "when": "2022-03-15T21:17:16Z",
    "ts": 1647379036,
    "source": "aws-cloudtrail",
    "what": "DescribeKey",
    "target": "arn:aws:kms:us-east-2:[123471887489:key/94c76869-d14f-4ca9-9980-a88be78f8f7b"
  },
  {
    "when": "2022-03-15T21:17:16Z",
    "who": "IAMUser <[123471887489/sdkmsusr/AKIA3DQTYPR7TLMRXTCS>",
    "ts": 1647379036,
    "source": "aws-cloudtrail",
    "target": "arn:aws:kms:us-east-2:[123471887489:key/94c76869-d14f-4ca9-9980-a88be78f8f7b",
    "what": "ImportKeyMaterial"
  },
  {
    "who": "IAMUser <[123471887489/sdkmsusr/AKIA3DQTYPR7TLMRXTCS>",
    "target": "arn:aws:kms:us-east-2:[123471887489:key/94c76869-d14f-4ca9-9980-a88be78f8f7b",
    "source": "aws-cloudtrail",
    "what": "GetParametersForImport",
    "ts": 1647379036,
    "when": "2022-03-15T21:17:16Z"
  },
  {
    "who": "IAMUser <[123471887489/sdkmsusr/AKIA3DQTYPR7TLMRXTCS>",
    "source": "aws-cloudtrail",
    "what": "ListResourceTags",
    "target": "arn:aws:kms:us-east-2:[123471887489:key/94c76869-d14f-4ca9-9980-a88be78f8f7b",
    "ts": 1647379036,
    "when": "2022-03-15T21:17:16Z"
  }
]
```

The latter operation first calls `merge-events` and then uses the specified input parameters to upload
the combined events in a single file to an Amazon S3 bucket object.
```
{
  "operation": "upload-events",
  "secret_id": "6c7cc3ec-1de6-4526-b272-1e3addd120b4",
  "bucket": "testbucket",
  "object_key": "fortanix-events"
}
```
Note that the Amazon S3 object key name taken from the input is programmatically appended with a timestamp
and .json extension, which will be output as follows:
```
{
  "key": "https://testbucket.s3.amazonaws.com/fortanix-events-1648160258.json"
}
```

## References

 * [Fortanix DSM Cloud Data Control with AWS Cloud KMS](https://support.fortanix.com/hc/en-us/articles/360055605471-User-s-Guide-AWS-External-KMS)
 * [Fortanix DSM Audit logs](https://support.fortanix.com/hc/en-us/articles/360016047631-User-s-Guide-Logging)
 * [AWS CloudTrail LookupEvents documentation](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.htm)
