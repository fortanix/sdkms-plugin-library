## Fortanix Data Security Manager (DSM) - Azure Key Vault Integration Plugin

## Introduction

This README provides an overview of the Fortanix DSM - Azure Key Vault Integration Plugin, which facilitates secret management between Fortanix Data Security Manager (DSM) and Azure Key Vault (AKV). The plugin offers various operations to interact with secrets in both DSM and AKV.

## Use Cases

This integration is designed to address the following use cases:

Create Secrets: This takes an existing secret from DSM and imports it into AKV
Import Secrets: Import an existing secret from AKV into DSM for secure management.
Import All Secrets: Import all secrets from AKV into DSM for comprehensive management.
List Secrets: Retrieve a list of secrets stored in AKV.
List Secret with Versions: Retrieve a list of versions for all secrets stored in AKV.
Delete Secret: Delete a secret from AKV.
List of Deleted Secrets: Provides list of deleted secrets from AKV.
Recover Secret: Recover a previously deleted secret in AKV.
Purge Secret: Permanently remove a deleted secret from AKV.


## Short Description
This integration offers a set of functions to allow for secure secret management between DSM and AKV. It's capable of importing, listing, deleting, recovering, purging secrets, and more. The plugin employs authentication via Azure Active Directory and leverages the Azure Key Vault REST API to perform these operations.

## Setup Process

Configure Azure Authentication:

Run the configure operation with the following parameters:
tenant_id: Your Azure AD Tenant ID.
client_id: Your Azure AD Client ID.
client_secret: Your Azure AD Client Secret.

## Perform Operations:

Call the desired operation by providing a JSON payload. Here's an example of how to call the import_secret function:

// This will import an existing secret in AKV and import it into DSM
{
  "operation": "import",
  "name": "secret-name",
  "version": "version",
  "key_vault": "key_vault",
  "secret_id": "secret-id"
}

You can replace "operation" with any of the supported operations (e.g., create, list_secrets, delete, import_all, etc.) and provide the required parameters.

API Response: The plugin will return a JSON response indicating the success or failure of the operation.

Replace "name", "version", "key_vault", and "secret-id" with your specific values. The plugin will then securely import the secret into DSM.

## Supported Operations
The following operations are supported by this plugin:

Create Secrets: This takes an existing secret from DSM and imports it into AKV
Import Secrets: Import an existing secret from AKV into DSM for secure management.
Import All Secrets: Import all secrets from AKV into DSM for comprehensive management.
List Secrets: Retrieve a list of secrets stored in AKV.
List Secret with Versions: Retrieve a list of versions for all secrets stored in AKV.
Delete Secret: Delete a secret from AKV.
List of Deleted Secrets: Provides list of deleted secrets from AKV.
Recover Secret: Recover a previously deleted secret in AKV.
Purge Secret: Permanently remove a deleted secret from AKV.

## Conclusion
The Fortanix DSM - Azure Key Vault Integration Plugin simplifies the management of secrets between Fortanix Data Security Manager and Azure Key Vault. It offers a range of operations to facilitate this integration securely. Follow the setup process and examples provided in this README to use the plugin effectively for your specific use cases.