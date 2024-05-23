#AWS Plugin for Secret Management with Fortanix DSM

#Introduction: 
This page provides an overview of a newly developed AWS plugin that leverages Fortanix Data Security Manager (DSM) for secure secret management within your AWS environment.

#Challenges of Managing Secrets in AWS:
    Security Risks: Secrets are highly sensitive data and storing them unencrypted or in plaintext poses significant security vulnerabilities. Accidental exposure, breaches, and insider threats can have devastating consequences.
    Manual Processes: Manually rotating, managing, and granting access to secrets is time-consuming, error-prone, and inefficient. This slows down workflows and increases the risk of human error.
    Lack of Centralized Control: Secrets often spread across different services and accounts, making it difficult to track, audit, and enforce consistent security policies.
    Compliance Complexity: Meeting compliance regulations requires stringent controls over secrets, which can be challenging with decentralized management.

Features
    Secure creation, rotation, and deletion of secrets
    Access control and granular permission management
    Integration with existing AWS services and IAM roles
    Audit logging and compliance reporting
    User-friendly interface for managing secrets



##Plugin Operations Guide:

--[[

Plugin Operations Guide:

1. Configure: Description: Sets up the plugin with necessary AWS credentials to enable communication with AWS services. These credentials are used for all operations that require AWS API calls, ensuring secure access to AWS Secrets Manager.
Operation: configure. Please note these operations are for the region 

Parameters:

secret_key: The secret access key part of your AWS credentials.
access_key: The access key ID part of your AWS credentials.

Sample JSON:

{
  "operation": "configure",
  "secret_key": "GZA....sz",
  "access_key": "AK...ZCX"
}

2. Create: Description: Creates a new secret within the local secret management system with the specified name and identifier. This operation is typically used to initialize a secret before importing its value from external sources or manually setting it.

Operation: create

Parameters:

name: The name to assign to the new secret.
secret_id: The identifier for the secret to be created.

Sample JSON:

{
  "operation": "create",
  "aws_secret_name": "nik12345678",
  "secret_value": "123",
  "secret_stages": "AWSCURRENT",
  "secret_id": "55ec7250-ffd1-4db7-8e5d-2"
}


3. List: Description: Lists the properties and current state of a secret managed by the local secret management system. This can include metadata such as creation date, last modified date, and version information.

Operation: list
Parameters:

secret_id: The identifier for the secret whose details are to be listed.

Sample JSON:

{
  "operation": "list",
  "secret_id": "55ec7250-ffd1-4db7-8e5d-"
}


4. List Versions: Description: Lists all versions of a specified secret, providing a history of changes and the ability to access previous values of the secret. This operation supports auditing and compliance by enabling tracking of secret updates over time.

Operation: list_versions

Parameters:
name: The name of the secret for which versions are to be listed.
secret_id: The identifier for the secret whose versions are to be listed.

Sample JSON:
{
  "operation": "list_versions",
  "name": "rotate1",
  "secret_id": "4ac0c969-5a82-4e5c-938a-"
}


5. Import from AWS: Description: Retrieves a specific version (or the latest) of a secret from AWS Secrets Manager and stores it locally, associating it with the provided secret_id. This operation ensures the secret is available within the local secret management system for use in applications or services.

Operation: import_from_aws

Parameters:

aws_secret_name: The name of the secret in AWS Secrets Manager.
aws_secret_version: The version of the secret to import. If not specified, the latest version is imported.
secret_id: The identifier for the secret where the AWS secret will be stored.

Sample JSON:

{
  "operation": "import_from_aws",
  "aws_secret_name": "aws7",
  "aws_secret_version": "6c3d9904-32f4-44f5-95ac-8f86e066e83b",
  "aws_version_stage": "AWSCURRENT",
  "secret_id": "4ac0c969-5a82-4e5c-938a-"
}

6. Import All Secrets from AWS: Description: Retrieves all secrets from AWS Secrets Manager and stores it locally, associating it with the provided secret_id. This operation ensures the secret is available within the local secret management system for use in applications or services.

Operation: import_all_secrets

Parameters:

secret_id: The identifier for the secret where the AWS secret will be stored.

Sample JSON:

{
  "operation": "import_all_secrets",
  "secret_id": "4ac0c969-5a82-4e5c-938a-"
}

7. Rotate: Description: Initiates a rotation process for the specified secret, creating a new version of the secret with a new value. This is essential for maintaining security by regularly updating secret values.

Operation: rotate

Parameters:
name: The name of the secret to rotate.
secret_id: The identifier for the secret to be rotated.

Sample JSON:

{
  "operation": "rotate",
  "secret_name": "plg4",
  "new_secret_value": "143",
  "secret_id": "4ac0c969-5a82-4e5c-938a-"
}

8. Delete: Description: Permanently removes a secret from the local secret management system. This operation is used to clean up secrets that are no longer needed, ensuring that outdated or sensitive information is securely managed and not left accessible.

Operation: delete
Parameters:

name: The name of the secret to be deleted.
secret_id: The identifier for the secret to be deleted.

Sample JSON: 

{
  "operation": "delete",
  "name": "aws1",
  "secret_id": "4ac0c969-5a82-4e5c-938a-"
}


9. Restore: Description: Restores a previously deleted or archived secret back into the active state within the local secret management system. This operation makes the secret available for use again.

Operation: restore

Parameters:

name: The name of the secret to be restored.
secret_id: The identifier for the secret to be restored.

Sample JSON:

{
  "operation": "restore",
  "name": "aws1",
  "secret_id": "4ac0c969-5a82-4e5c-938a-"
}


10. Export: Exports a secret from Fortanix DSM to AWS Secret Manager.

Operation: Export

Parameters:

dsm_secret_name": the name of secret in dsm 
aws_secret_name": the of secret which has to be in AWS secret manager
aws_secret_version": Version Id of aws secret 
aws_version_stage": 
secret_id": 


name: The name of the secret to be restored.
secret_id: The identifier for the secret to be restored.

Sample JSON:

{
  "operation": "export",
  "dsm_secret_name": "export21",
  "aws_secret_name": "export21",
  "aws_secret_version": "6c3d9904-32f4-44f5-95ac-8f86e066e83b",
  "aws_version_stage": "AWSCURRENT",
  "secret_id": "4ac0c969-5a82-4e5c-938a-"
}

Note: If you require these operations to be executed in regions other than us-west-1, kindly modify the region in the following loc and functions:
 -- function aws_request, loc - 209
 
