--[[
// Configure client credentials
{
  "operation": "configure",
  "tenant_id": "de7becae...88ae6",
  "client_id": "f8d7741...6abb6",
  "client_secret": "SvU...5"
}

// Create Secret: This takes an existing secret from DSM and imports it into AKV
{
  "operation": "create",
  "name": "fix1",
  "key_vault": "test-keyvault",
  "exp": 1596240000,
  "secret_id": "84480fb2-4290-4bf4-bbea-588e877efd44"
}

// Import Secrets: Import an existing secret from AKV into DSM for secure management.
{
  "operation": "import",
  "name": "nik123",
  "version": "a6398c1db7b546fd8c7af255cf8fd926",
  "key_vault": "test-keyvault",
  "secret_id": "fa7881b9-ae19-4c01-bef4-a6c0a4c8f618"
}

// Import All Secrets: Import all secrets from AKV into DSM for comprehensive management.
{
  "operation": "import_all",
  "key_vault": "test-keyvault",
  "secret_id": "0bc44912-51c6-459d-929f-b61b1a3612bc"
}

//List Secrets: Retrieve a list of secrets stored in AKV.
{
  "operation": "list_secrets",
  "key_vault": "test-keyvault",
  "secret_id": "0bc44912-51c6-459d-929f-b61b1a3612bc"
}

// List Secret Versions: Retrieve a list of versions for a specific secret stored in AKV.
{
  "operation": "list_secret_versions",
  "key_vault": "test-keyvault",
  "secret_id": "0bc44912-51c6-459d-929f-b61b1a3612bc"
}

// Delete Secret: Delete a secret from AKV.
{
  "operation": "delete_secret",
  "secret_id": "84480fb2-4290-4bf4-bbea-588e877efd44",
  "key_vault": "test-keyvault",
  "name": "nik30"
}

// List of Deleted Secrets: Provides list of deleted secrets from AKV.
{
  "operation": "list_deleted_secrets",
  "secret_id": "0e2c407c-fead-4b72-9c3e-0e3f6fbc9cef",
  "key_vault": "test-keyvault"
}


// Recover Secret: Recover a previously deleted secret in AKV.
{
  "operation": "recover_secret",
  "secret_id": "5cf1cd73-d931-476e-b92c-011fac234d1e",
  "key_vault": "test-keyvault",
  "name": "nik61"
}

// Purge Secret: Permanently remove a deleted secret from AKV.
{
  "operation": "purge_secret",
  "secret_id": "5cf1cd73-d931-476e-b92c-011fac234d1e",
  "key_vault": "test-keyvault",
  "name": "nik5-secret"
}
--]]
-- Declare a global variable for API version
API_VERSION = '7.4'
offset = 0
function save_credentials(tenant_id, client_id, client_secret)
  local name = Blob.random { bits = 64 }:hex()
  local secret = assert(Sobject.import{ name = name, obj_type = 'SECRET', value = Blob.from_bytes(client_secret), custom_metadata = {['TenantId'] = tenant_id, ['ClientId'] = client_id }})
  return {secret_id = secret.kid}
end
function login(secret_id)
local sobject, err = Sobject { id = secret_id }
  if sobject == nil
then
return {result = nil, error = err, message = "Azure cloud credential is not configure or invalid. Please run configure operation."}
  end
if sobject.custom_metadata == nil
then
return {result = nil, error = err, message = "Azure cloud credential is not configure or invalid. Please run configure operation."}
  end
if sobject.custom_metadata['TenantId'] == nil
or sobject.custom_metadata['ClientId'] == nil
then 
return {result = nil, error = err, message = "Azure cloud credential is not configure or invalid. Please run configure operation."}
  end
  -- Retrieve custom metadata from the sobject once
  local custom_metadata = sobject.custom_metadata
  local client_secret = sobject:export().value:bytes()
  local tenant_id = custom_metadata['TenantId']
  local client_id = custom_metadata['ClientId']
  local headers = { ['Content-Type'] = 'application/x-www-form-urlencoded'}
  local url = 'https://login.microsoftonline.com/'.. tenant_id ..'/oauth2/token' 
local request_body = 'grant_type=client_credentials&client_id='..client_id..'&client_secret='..client_secret..'&resource=https%3A%2F%2Fvault.azure.net'
local response, err = request { method = 'POST', url = url, headers = headers, body=request_body }
  if err ~= nil then
    return {result = nil, error = err}
  end
  if response.status ~= 200 then
    return {result = nil, error = json.decode(response.body),  message = "Secret not found"}
  end
  return {result = json.decode(response.body).access_token, error = nil}
end

function import_secret_into_akv(headers, key_vault, name, exp)
  -- Find the secret in DSM
  local sobject, err = Sobject {name = name}
  if sobject == nil or err ~=nil then
    return {result = sobject, error = err, message = "Create BYOS operation fail."}
  end
  local value = sobject:export().value:bytes()
  local attributes = { exp = exp  }
  request_body = {
    value =  value,
    attributes = attributes,
    tags = {
      KeyType = 'BYOK',
      KMS = 'DSM'
    }
  }
  local url = 'https://'.. key_vault ..'.vault.azure.net/secrets/'.. name ..'?api-version=' .. API_VERSION
  local response, err = request { method = 'PUT', url = url, headers = headers, body=json.encode(request_body)}
  if err ~= nil or response.status ~= 200 then
    return {result = response, error = err, message = 'Create BYOK operation fail.'}
  end
  return {result = json.decode(response.body), error = nil}
end

-- Include the base64 encoding function
local base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
function base64_encode(data)
    local bytes = {}
    local len = string.len(data)
    local padding = 3 - (len % 3)
    -- Check if the data is empty
    if len == 0 then
        return ""  -- Return an empty string for empty input
    end
    -- Ensure that the data is properly padded
    local padding = (3 - len % 3) % 3
    data = data .. string.rep("\0", padding)
    -- Encode the data in groups of 3 bytes
    for i = 1, len, 3 do
        local b1, b2, b3 = string.byte(data, i, i + 2)
        local group = (b1 << 16) + (b2 << 8) + b3
        for j = 0, 3 do
            local index = (group >> (18 - j * 6)) & 63
            bytes[#bytes + 1] = base64_chars:sub(index + 1, index + 1)
        end
    end
    for i = 1, padding do
        bytes[#bytes - i + 1] = "="
    end
    return table.concat(bytes)
end
-- input secret into DSM

function import_secret_into_dsm(headers, key_vault, name, version)
    local url = 'https://' .. key_vault .. '.vault.azure.net/secrets/' .. name .. '/' .. version .. '?api-version=' .. API_VERSION
    local response, err = request { method = 'GET', url = url, headers = headers, body = '' }
    if err ~= nil or response.status ~= 200 then
        return { result = response, error = err, message = 'Could not obtain secret from AKV' }
    end
    local response_body = json.decode(response.body)
    -- Base64 encode the secret value
    local base64_encoded_value = base64_encode(response_body.value)
    -- Import into DSM with the original version
    local sobject, err = Sobject.import { name = name .. '/' .. version, obj_type = 'SECRET', value = base64_encoded_value }
    if sobject == nil then
        return { result = nil, error = err }
    end
    return { result = json.decode(response.body), error = nil }
end

function extract_name_and_version(id)
  -- Split the URL by '/'
  local parts = {}
  for part in string.gmatch(id, "[^/]+") do
      table.insert(parts, part)
  end
  -- The "name" is the second-to-last part
  local name = parts[#parts - 1]
  -- The "version" is the last part
  local version = parts[#parts]
  return name, version
end

-- Import Secrets: Import an existing secret from AKV into DSM for secure management.

function import_secret_version_into_dsm(headers, url)
  -- Check if version is nil
  if url == nil then
      return { result = nil, error = "Version is nil" }
  end
  local response, err = request { method = 'GET', url = url, headers = headers, body = '' }
  if err ~= nil or response.status ~= 200 then
      return { result = response, error = err, message = 'Could not obtain secret from AKV' }
  end
  local response_body = json.decode(response.body)
  -- Base64 encode the secret value
  local base64_encoded_value = base64_encode(response_body.value)
  -- Import into DSM with the original version
  local name, version = extract_name_and_version(url)
  local sobject, err = Sobject.import { name = name .. '/' .. version, obj_type = 'SECRET', value = base64_encoded_value }
  if sobject == nil then
	  print ()
      return { result = nil, error = err }
  end
  return { result = json.decode(response.body), error = nil }
end

-- Import All Secrets: Import all secrets from AKV into DSM for comprehensive management.

function import_all_secrets_from_akv(headers, key_vault)
    -- Get the list of secrets from Azure Key Vault
    local secrets_response = list_secrets(headers, key_vault)  
    if secrets_response.error then
      return { results = nil, error = secrets_response.error }
    end
    local secrets = secrets_response.result or {}  
    local import_results = {}  -- Initialize the results table  
    for _, secret in ipairs(secrets) do
      for _, s_value in ipairs(secret.value) do
          local id = s_value.id
          local versions_url = id .. '/versions?api-version=' .. API_VERSION
          local versions_response = list_versions(headers, versions_url) 
          if versions_response.error then
              table.insert(import_results, { result = nil, error = versions_response.error, message = 'Could not list versions for ' .. id })
          else
              local versions = versions_response.result or {} 
              for _, version in ipairs(versions) do
                    for _, v_value in ipairs(version.value) do
                      -- Import the secret and its version into the DSM group
                        local version_id = v_value.id
                      local version_url = version_id .. '?api-version=' .. API_VERSION
                      local name, secret_version = extract_name_and_version(version_id)
                      local result = import_secret_into_dsm(headers, key_vault, name, secret_version)		
                      if result.error then
                          table.insert(import_results, { result = nil, error = result.error, message = 'Could not import secret for ' .. version_id })
                      else
                          table.insert(import_results, { result = result.result, error = nil })
                      end
                    end
              end
            end
        end
      end 
    -- Return the import results
    return { results = import_results, error = nil }
  end
  
  
  -- List Secrets: Retrieve a list of secrets stored in AKV.

  function list_secrets(headers, key_vault)
    local result = {}  -- Initialize the result table
    local continuation_token = nil
    repeat
      local url = 'https://' .. key_vault .. '.vault.azure.net/secrets?api-version=' .. API_VERSION
      if continuation_token then
        url = url .. '&continuationToken=' .. continuation_token
      end
      local response, err = request { method = 'GET', url = url, headers = headers, body = '' }
      if err ~= nil or response.status ~= 200 then
        return {result = result, error = err, message = "Something went wrong. Can't list the secrets."}
      end
      local response_body = json.decode(response.body)
      table.insert(result, response_body or {} )
      -- Check for continuation token
      continuation_token = type(response_body.nextLink) == "table" and response_body.nextLink.continuationToken
    until not continuation_token
    return {result = result, error = nil}
  end
  
  -- list version of secrets 
  function list_versions(headers, url)
    local result = {}  -- Initialize the result table
    local continuation_token = nil
    repeat
      local full_url = url
      if continuation_token then
        full_url = url .. '&continuationToken=' .. continuation_token
      end
      local response, err = request { method = 'GET', url = full_url, headers = headers, body = '' }
      if err ~= nil or response.status ~= 200 then
        return {result = result, error = err, message = "Something went wrong. Can't list the versions."}
      end
      local response_body = json.decode(response.body)
      table.insert(result, response_body or {})
      -- Check for continuation token
      continuation_token = type(response_body.nextLink) == "table" and response_body.nextLink.continuationToken
    until not continuation_token
    return {result = result, error = nil}
  end

-- List Secret with Versions: Retrieve a list of versions for all secrets stored in AKV.

function display_all_secrets_with_versions(headers, key_vault)
    -- Get the list of secrets from Azure Key Vault
    local secrets_response = list_secrets(headers, key_vault)  
    if secrets_response.error then
      return { results = nil, error = secrets_response.error }
    end
    local secrets = secrets_response.result or {}  
    local import_results = {}  -- Initialize the results table  
    for _, secret in ipairs(secrets) do
      for _, s_value in ipairs(secret.value) do
          local id = s_value.id
          local versions_url = id .. '/versions?api-version=' .. API_VERSION
          local versions_response = list_versions(headers, versions_url) 
          if versions_response.error then
              table.insert(import_results, { result = nil, error = versions_response.error, message = 'Could not list versions for ' .. id })
          else
              local versions = versions_response.result or {} 
              for _, version in ipairs(versions) do
                    for _, v_value in ipairs(version.value) do
                        -- Display the secret and its version
                        local version_id = v_value.id
                        local name, secret_version = extract_name_and_version(version_id)
                        table.insert(import_results, { secret_name = name, version = secret_version })
                    end
              end
            end
        end
      end 
    -- Return the import results
    return { results = import_results, error = nil }
end
  
 -- Delete Secret: Delete a secret from AKV.

function delete_secret(headers, key_vault, name)
  local url = 'https://' .. key_vault .. '.vault.azure.net/secrets/' .. name .. '?api-version=' .. API_VERSION
  local response, err = request { method = 'DELETE', url = url, headers = headers, body = '' }
  if err ~= nil or response.status ~= 200 then
    return { result = response, error = err, message = "Something went wrong. Can't delete the secret." }
  end
  return {result = json.decode(response.body), error = nil}
end

-- List of Deleted Secrets: Provides list of deleted secrets from AKV.

function list_deleted_secrets(headers, key_vault)
  local url = 'https://'.. key_vault ..'.vault.azure.net/deletedsecrets?api-version=' .. API_VERSION
  local response, err = request { method = 'GET', url = url, headers = headers, body = '' }
  if err ~= nil or response.status ~= 200 then
    return { result = response, error = err, message = "Something went wrong. Can't get deleted secrets." }
  end
  return {result = json.decode(response.body), error = nil}
end

-- Purge Secret: Permanently remove a deleted secret from AKV.

function purge_secret(headers, key_vault, name)
    local url = 'https://'.. key_vault ..'.vault.azure.net/deletedsecrets/'.. name .. '?api-version=' .. API_VERSION
    local response, err = request { method = 'DELETE', url = url, headers = headers, body = '' }
    if err ~= nil or response.status ~= 204 then
        return { result = response, error = err, message = "Something went wrong. Can't purge the secret." }
      end
      return {result = json.decode(response.body), error = nil}
    end

--Recover Secret: Recover a previously deleted secret in AKV.

function recover_secret(headers, key_vault, name)
  local url = 'https://'.. key_vault ..'.vault.azure.net/deletedsecrets/'.. name .. '/recover?api-version=' .. API_VERSION
  local response, err = request { method = 'POST', url = url, headers = headers, body = '' }
  if err ~= nil or response.status ~= 200 then
    return {result = response, error = err, message = "Something went wrong. Can't recover the secret."}
  end
  return {result = json.decode(response.body), error = nil}
end

function is_valid_sdkms_key(name)
  local response, err = Sobject {name = name}
  if err ~= nil or response == nil then
    return false
  end
  return true
end

function is_valid_cloud_key(headers, key_vault, name, version)
  local url = 'https://'.. key_vault ..'.vault.azure.net/secrets/'..name.. '?api-version=' .. API_VERSION
  local response, err = request {method = 'GET', url = url, headers = headers, body = ''}
  if err ~= nil or response.status ~= 200 then
    return false
  end
  return true
end

function is_valid_cloud_key_from_deleted_list(headers, key_vault, name)
  local url = 'https://'.. key_vault ..'.vault.azure.net/deletedsecrets/'..name.. '?api-version=' .. API_VERSION
  local response, err = request {method = 'GET', url = url, headers = headers, body = ''}
  if err ~= nil or response.status ~= 200 then
    return false
  end
  return true
end

function has_value(operation)
  local opr = {'configure', 'create', 'import', 'import_all', 'list_versions', 'list_secret_versions', 'delete_secret', 'list_secrets', 'list_deleted_secrets', 'recover_secret', 'purge_secret'}
  for i=1,#opr do
    if opr[i] == operation then
      return true
    end
  end
  return false
end

function is_valid(operation)
  local opr = {'configure', 'create', 'import', 'import_all', 'list_versions', 'list_secret_versions', 'delete_secret', 'list_secrets', 'list_deleted_secrets', 'recover_secret', 'purge_secret'}
  for i=1,#opr do
    if opr[i] == operation then
      return true
    end
  end
  return false
end

-- Check input parameters based on the operation
function check(input)
  if input.operation == 'configure' then
    if input.tenant_id == nil then
      return nil, 'input parameter tenant_id required'
    end
    if input.client_id == nil then
      return nil, 'input parameter client_id required'
    end
    if input.client_secret == nil then
      return nil, 'input parameter client_secret required'
    end
  elseif input.operation == 'create' then
    if input.secret_id == nil then
      return nil, 'input parameter secret_id required'
    end
    if input.key_vault == nil then
      return nil, 'input parameter key_vault required'
    end
    if input.name == nil then
      return nil, 'input parameter name required'
    end
    if input.exp == nil then
      return nil, 'input parameter exp required'
    end
  elseif input.operation == 'import' then
    if input.secret_id == nil then
      return nil, 'input parameter secret_id required'
    end
    if input.key_vault == nil then
      return nil, 'input parameter key_vault required'
    end
    if input.name == nil then
      return nil, 'input parameter name required'
    end
    if input.version == nil then
      return nil, 'input parameter version required'
    end
  elseif input.operation == 'import_all' then
    if input.secret_id == nil then
      return nil, 'input parameter secret_id required'
    end
    if input.key_vault == nil then
      return nil, 'input parameter key_vault required'
    end
  elseif input.operation == 'list_secrets' then
    if input.secret_id == nil then
      return nil, 'input parameter secret_id required'
    end
    if input.key_vault == nil then
      return nil, 'input parameter key_vault required'
    end
  elseif input.operation == 'list_secret_versions' then
    if input.secret_id == nil then
      return nil, 'input parameter secret_id required'
    end
  elseif input.operation == 'delete_secret' then
    if input.secret_id == nil then
      return nil, 'input parameter secret_id required'
    end
    if input.key_vault == nil then
      return nil, 'input parameter key_vault required'
    end
    if input.name == nil then
      return nil, 'input parameter name required'
    end
  elseif input.operation == 'list_deleted_secrets' then
    if input.secret_id == nil then
      return nil, 'input parameter secret_id required'
    end
    if input.key_vault == nil then
      return nil, 'input parameter key_vault required'
    end
  elseif input.operation == 'recover_secret' then
    if input.secret_id == nil then
      return nil, 'input parameter secret_id required'
    end
    if input.key_vault == nil then
      return nil, 'input parameter key_vault required'
    end
    if input.name == nil then
      return nil, 'input parameter name required'
    end
  elseif input.operation == 'purge_secret' then
    if input.secret_id == nil then
      return nil, 'input parameter secret_id required'
    end
    if input.key_vault == nil then
      return nil, 'input parameter key_vault required'
    end
    if input.name == nil then
      return nil, 'input parameter name required'
    end
  end
  return true
end
function run(input)
  if not is_valid(input.operation) then
      return {result = 'Operation is not valid. Operation value should be one of configure, create, import, import_all, list_secrets, list_versions, delete, list_deleted_secrets, recover_secret, purge_secret', error = nil}
  end
  if input.operation == 'configure' then
      return save_credentials(input.tenant_id, input.client_id, input.client_secret)
  else
      --[[Authentication]]--
      local resp, err, message = login(input.secret_id)
      if resp.result == nil then
          return {result = resp, error = err, message = message}
      end
      local authorization_header = 'Bearer ' .. resp.result
      headers = {['Content-Type'] = 'application/json', ['Authorization'] = authorization_header}
      if input.operation == 'create' then
          if is_valid_cloud_key(headers, input.key_vault, input.name, input.operation) then
              return "Something went wrong or secret already exists in Azure cloud or does not exist in DSM"
          end
          return import_secret_into_akv(headers, input.key_vault, input.name, input.exp)
      elseif input.operation == 'import' then
          -- Check if version is nil
          if input.version == nil then
              return {result = nil, error = "Version is nil"}
          end
          -- Ensure version is not an empty string
          if input.version == "" then
              return {result = nil, error = "Invalid version"}
          end
          if not (is_valid_cloud_key(headers, input.key_vault, input.name, input.version)) or is_valid_sdkms_key(input.name) then
              return "Something went wrong or secret does not exist in Azure cloud or already exists in DSM"
          end
          return import_secret_into_dsm(headers, input.key_vault, input.name, input.version)
      elseif input.operation == 'import_all' then
          return import_all_secrets_from_akv(headers, input.key_vault)
      elseif input.operation == 'delete_secret' then
          if not (is_valid_cloud_key(headers, input.key_vault, input.name)) then
              return "Something went wrong or the secret does not exist in Azure cloud."
          end
          return delete_secret(headers, input.key_vault, input.name)
      elseif input.operation == 'list_deleted_secrets' then
          return list_deleted_secrets(headers, input.key_vault)
      elseif input.operation == 'recover_secret' then
          if not (is_valid_cloud_key_from_deleted_list(headers, input.key_vault, input.name)) and is_valid_sdkms_key(input.key_name) then
              return "Something went wrong or the secret does not exist in Azure cloud."
          end
          return recover_secret(headers, input.key_vault, input.name)
      elseif input.operation == 'purge_secret' then
          if not (is_valid_cloud_key_from_deleted_list(headers, input.key_vault, input.name)) then
              return "Something went wrong or the secret does not exist in Azure cloud."
          end
          return purge_secret(headers, input.key_vault, input.name)
      elseif input.operation == 'list_secrets' then
          return list_secrets(headers, input.key_vault)
      elseif input.operation == 'list_secret_versions' then
          do return display_all_secrets_with_versions(headers, input.key_vault) end
       return {result = 'Operation is not valid. Operation value should be one of configure, create, import, import_all, list_secrets, list_versions, delete, list_deleted_secrets, recover_secret, purge_secret', error = nil}
      end
  end
end