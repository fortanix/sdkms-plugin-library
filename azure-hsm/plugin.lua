--[[
configure operation
{
   "operation": "configure",
   "tenant_id": "de7becae...88ae6",
   "client_id": "f8d7741...6abb6",
   "client_secret": "SvU...5"
}

create operation
{
  "operation": "create",
  "key_name": "test-key",
  "key_vault": "test-hsm-keyvault",
  "kek_key_kid": "https://test-hsm-keyvault.vault.azure.net/keys/test-kek-key/0ffc59a57f664b9fbde6455bd0ed5dd5",
  "secret_id": "75803498-b97f-430e-8fd3-bfd995ffe958"
}

list key
{
  "operation": "list",
  "key_vault": "test-hsm-keyvault",
  "secret_id": "75803498-b97f-430e-8fd3-bfd995ffe958"
}

delete key
{
  "operation": "delete",
  "key_name": "test-key",
  "key_vault": "test-hsm-keyvault",
  "secret_id": "75803498-b97f-430e-8fd3-bfd995ffe958"
}

restore key
{
  "operation": "restore",
  "key_name": "test-key",
  "key_vault": "test-hsm-keyvault",
  "secret_id": "75803498-b97f-430e-8fd3-bfd995ffe958"
}

]]--

TOOL_NAME = 'SDKMS Azure HSM BYOK'
TOOL_VERSION = '0.0.2'
SCHEMA_VERSION = '1.0.0'
-- Update with SDKMS current version
FIRMWARE_VERSION = '3.16.1311'

function prepad_signed(str)
  local msb = tonumber(string.sub(str, 0, 1), 16)
  if (msb < 0 or msb > 7) then
    return '00'.. str
  else
    return str
  end
end

function base64url_encode(str)
  local blob = Blob.from_bytes(str)
  local base64 = blob:base64()
  local base64 = base64:gsub('+', '-')
  base64 = base64:gsub('/', '_')
  base64 = base64:gsub('=', '')
  return base64
end

function save_credentials(tenant_id, client_id, client_secret, credential_group_id)
  local name = Blob.random { bits = 64 }:hex()
  local secret, err = Sobject.import{ name = name, obj_type = 'SECRET', value = Blob.from_bytes(client_secret), group_id = credential_group_id, custom_metadata = {['TenantId'] = tenant_id, ['ClientId'] = client_id }}
  if secret == nil then
    err.message = err.message .. '. Failed to configure Azure credentials'
    return {secret_id = nil, error = err}
  end
  return {secret_id = secret.kid, error = nil}
end

function login(secret_id)
  local sobject, err = Sobject { id = secret_id }
  if sobject == nil then
    return {result = nil, error = err, message = "Azure cloud credentials are not configured, or invalid. Please run configure operation."}
  end
  if sobject.custom_metadata == nil then
    return {result = nil, error = err, message = "Azure cloud credentials are not configured, or invalid. Please run configure operation."}
  end
  if sobject.custom_metadata['TenantId'] == nil or sobject.custom_metadata['ClientId'] == nil then
    return {result = nil, error = err, message = "Azure cloud credentials are not configured, or invalid. Please run configure operation."}
  end
  local client_secret = sobject:export().value:bytes()
  local tenant_id = Sobject { id = secret_id }.custom_metadata['TenantId']
  local client_id = Sobject { id = secret_id }.custom_metadata['ClientId']
  local headers = { ['Content-Type'] = 'application/x-www-form-urlencoded'}
  local url = 'https://login.microsoftonline.com/'.. tenant_id ..'/oauth2/token'
  local request_body = 'grant_type=client_credentials&client_id='..client_id..'&client_secret='..client_secret..'&resource=https%3A%2F%2Fvault.azure.net'
  local response, err = request { method = 'POST', url = url, headers = headers, body=request_body }
  if err ~= nil then
    return {result = nil, error = err}
  end
  if response.status ~= 200 then
    return {result = nil, error = json.decode(response.body)}
  end
  return {result = json.decode(response.body).access_token, error = nil}
end

function config_kek_key(headers, kek_key_kid, source_group_id, is_transient)
  -- TODO: Remove hardcoded values
  -- only work for 2048 kek key
  local prefix = '30820122300D06092A864886F70D01010105000382010F003082010A02820101'
  local suffix = '0203010001'
  local url = kek_key_kid .. '?api-version=7.0'
  local response, err = request { method = 'GET' , url = url, headers = headers, body='' }
  if err ~= nil then
    return {result = nil, error = err}
  end
  if response.status ~= 200 then
    return {result = nil, error = response}
  end
  local json_resp = json.decode(response.body)
  local modulus = json_resp['key']['n']
  local name = Blob.random { bits = 64 }:hex()
  local encoded_kek_key = prefix ..  prepad_signed(Blob.from_base64(modulus):hex()) ..suffix
  local sobject, err = Sobject.import { name = name, obj_type = 'RSA', value = Blob.from_hex(encoded_kek_key), key_ops = {'EXPORT', 'WRAPKEY'}, group_id = source_group_id, transient = is_transient }
  if sobject == nil then
    err.message = err.message .. '. Failed to import KEK key in DSM.'
    return {result = nil, error = err}
  end
  return {result = sobject, error = nil}
end

function create_wrapping_key(source_group_id, is_transient)
  local name = Blob.random { bits = 64 }:hex()
  local sobject, err = Sobject.create { name = name, obj_type = 'AES', key_size = 256, key_ops = {'EXPORT', 'WRAPKEY'}, group_id = source_group_id, transient = is_transient}
  if sobject == nil then
    err.message = err.message .. '. Failed to create wrapping key in DSM.'
    return {result = nil, error = err}
  end
  return {result = sobject, error = nil}
end

function create_target_key(name, source_group_id)
  local sobject = Sobject { name = name }
  if sobject ~= nil then
    return {result = sobject, error = nil}
  end
  local sobject, err = Sobject.create { name = name, obj_type = "RSA", key_size = 2048, key_ops = {'EXPORT'}, group_id = source_group_id,}
  if sobject == nil then
    err.message = err.message .. '. Failed to create target key in DSM.'
    return {result = nil, error = err}
  end
  return {result = sobject, error = nil}
end

function wrap_wrapping_key(wrapping_key, kek_key)
  local wrap_response, err = kek_key:wrap { subject = wrapping_key, mode = 'OAEP_MGF1_SHA1', alg = 'RSA'}
  if wrap_response == nil then
    err.message = err.message .. '. Failed to wrap wrapping key.'
    return {result = nil, error = err}
  end
  return {result = wrap_response.wrapped_key:bytes(), error = nil}
end

function wrap_target_key(wrapping_key, target_key)
  local wrap_response, err = wrapping_key:wrap { subject = target_key, mode = 'KWP', alg = 'AES', key_format = 'Pkcs8' }
  if wrap_response == nil then
    err.message = err.message .. '. Failed to wrap target key.'
    return {result = nil, error = err}
  end
  return {result = wrap_response.wrapped_key:bytes(), error = nil}
end

function generate_byok(wrapped_wrapping_key, wrapped_target_key, kek_key_kid)
  local header = "{'kid': " .. "'" .. kek_key_kid .. "'" .. ", 'alg': 'dir', 'enc': 'CKM_RSA_AES_KEY_WRAP'}"
  local generator = "'" .. TOOL_NAME .. ', Version : ' .. TOOL_VERSION .. '; Fortanix DSM Firmware version : ' .. FIRMWARE_VERSION .. "'"
  local ciphertext = "'" .. base64url_encode(wrapped_wrapping_key .. wrapped_target_key) .."'"
  local byok = "{'schema_version':"..  "'" .. SCHEMA_VERSION .. "'" .. ", 'header': " ..header  .. ", 'ciphertext': ".. ciphertext ..", 'generator': " ..generator .. "}"
  return byok
end

function perform_byok(headers, byok, name, key_vault)
  local url = "https://" .. key_vault .. ".vault.azure.net/keys/" .. name .. "?api-version=7.0"
  local b64 = Blob.from_bytes(byok):base64()
  local body = "{ 'key': { 'kty': 'RSA-HSM', 'key_hsm':".. "'" .. b64 .. "'" .. "} }"
  local response, err = request { method = "PUT", url = url, headers = headers, body=body }
  if err ~= nil then
    return {result = nil, error = err}
  end
  if response.status ~= 200 then
    return {result = nil, error = response}
  end
  -- Update target key
  local sobject = Sobject { name = name }
  local azure_kid = json.decode(response.body).key.kid
  sobject:update{custom_metadata = { AZURE_KEY_ID = azure_kid }}

  -- Backup the Azure key
  local backup_resp, err = backup_key (headers, key_vault, name, azure_kid)
  if err ~= nil then
    return {result = nil, error = err}
  end

  return {result = json.decode(response.body), error = nil}
end

function list_keys(headers, key_vault)
  local url = 'https://'.. key_vault ..'.vault.azure.net/keys?api-version=7.0'
  local response, err = request { method = 'GET', url = url, headers = headers, body='' }
  if err ~= nil or response.status ~= 200 then
    return {result = response, error = err, message = "Something went wrong. Can't list the keys."}
  end
  return {result = json.decode(response.body), error = nil}
end

function delete_key(headers, key_vault, key_name)
  local url = 'https://'.. key_vault ..'.vault.azure.net/keys/'.. key_name ..'?api-version=7.0'
  local response = request { method = 'DELETE', url = url, headers = headers, body='' }
  if err ~= nil or response.status ~= 200 then
    return {result = response, error = err, message = "Something went wrong. Can't delete the key."}
  end
  return {result = json.decode(response.body), error = nil}
end

function is_valid(operation)
  local opr = {'configure', 'create', 'copy', 'delete', 'list', 'restore'}
  for i=1,#opr do
    if opr[i] == operation then
      return true
    end
  end
  return false
end

function is_valid_sdkms_key(name)
  local response, err = Sobject {name = name}
  if err ~=nil or response == nil then
    return false
  end
  return true
end

function is_valid_group(group_id)
  local response, err = Group {group_id = group_id}
  if err ~=nil or response == nil then
    return false
  end
  return true
end

function is_external_hsm_group(group_id)
  local response, err = Group {group_id = group_id}
  if err then
    return false
  end
  return response.hmg ~= nil
end

function is_valid_cloud_key(headers, key_vault, name)
  url = 'https://'.. key_vault ..'.vault.azure.net/keys/'..name..'?api-version=7.0'
  local response, err = request {method = 'GET', url = url, headers = headers, body = ''}
  if err ~= nil or response.status ~= 200 then
    return false
  end
  return true
end

function backup_key(headers, key_vault, key_name, azure_kid)
  local url = 'https://'.. key_vault ..'.vault.azure.net/keys/'.. key_name ..'/backup?api-version=7.0'
  local response, err = request { method = 'POST', url = url, headers = headers, body='' }
  if err ~= nil or response.status ~= 200 then
    return {result = response, error = err, message = "Something went wrong. Can't backup the key."}
  end
  local blob = json.decode(response.body).value

  local backup_name = key_name .. '_azure_backup'

  -- rename the old backup
  local prev_backupSo, err  = Sobject { name = backup_name }
  if err == nil then
	  local prev_azure_kid = prev_backupSo.custom_metadata['AZURE_KEY_ID']
	  local rename_backupSo = backup_name .. '_version_' .. prev_azure_kid
	  prev_backupSo:update {name = rename_backupSo}
  end

  -- import as opaque object
  local sobject = assert(Sobject.import { name = backup_name, obj_type = "OPAQUE", value = Blob.from_base64(blob), key_ops = {'EXPORT'}, custom_metadata = { AZURE_KEY_ID = azure_kid }})

  return {result = sobject, error = nil}
end

function restore_key(headers, key_vault, name)
 local url = 'https://'..key_vault..'.vault.azure.net/keys/restore?api-version=7.0'
  local backup_keyname = name .. '_azure_backup'
  local backupSo, err = Sobject { name = backup_keyname }
  if err ~= nil then
    return {result = response, error = err, message = "Backup not found"}
  end

  local exported_value = backupSo:export().value
  local body = {
    value = exported_value
  }
  local response, err = request { method = 'POST', url = url, headers = headers, body = json.encode(body) }
  if err ~= nil or response.status ~= 200 then
    return {result = response, error = err, message = "Something went wrong. Can't restore the key."}
  end
  return response
end


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
  elseif input.operation == 'create' or input.operation == 'copy' or input.operation == 'restore' then
    if input.key_name == nil then
      return nil, 'input parameter key_name required'
    end
    if input.key_vault == nil then
      return nil, 'input parameter key_vault required'
    end
    if input.secret_id == nil then
      return nil, 'input parameter secret_id required'
    end
  end
end

function run(input)
  if not is_valid(input.operation) then
    return {result = nil, error = "Operation is not valid. Operation value should be one of `configure`, `create`, `copy`, `list`, or `delete`."}
  end

  if input.operation == 'configure' then
    if input.credential_group_id ~= nil and not is_valid_group(input.credential_group_id) then
      return "Credential group id is invalid or not accessible"
    end
    if is_external_hsm_group(input.credential_group_id) then
      return "Credential group id is an external HSM group. Can not create secret object to store Azure credentials in this group"
    end
    return save_credentials(input.tenant_id, input.client_id, input.client_secret, input.credential_group_id)
  else
    local resp, err, message = login(input.secret_id)
    if resp.result == nil then
      return {result = resp, error = err, message = message}
    end
    local authorization_header = 'Bearer ' ..resp.result
    headers = {['Content-Type'] = 'application/json', ['Authorization'] = authorization_header}
    if input.operation == 'create' or input.operation == 'copy' then
      if (input.rotate_key_in_azure ~= true or input.operation == 'create') and is_valid_cloud_key(headers, input.key_vault, input.key_name) then
        return "Something went wrong, or the key already exists in Azure cloud."
      end
      if input.operation == 'create' and is_valid_sdkms_key(input.key_name) then
        return "Something went wrong, or the key already exists in DSM."
      end
      if input.operation == 'copy' and not is_valid_sdkms_key(input.key_name) then
        return "The key does not exist in DSM. Can not copy"
      end

      if input.source_group_id ~= nil then
        if is_external_hsm_group(input.source_group_id) then
          is_transient = false
        else
          is_transient = true
        end
      else
        is_transient = true
      end

      local config_kek_key_resp = config_kek_key(headers, input.kek_key_kid, input.source_group_id, is_transient)
      if config_kek_key_resp.result == nil then
        return config_kek_key_resp
      end
      -- create wrapping key used to wrap target key
      local wrapping_key = create_wrapping_key(input.source_group_id, is_transient)
      if wrapping_key.result == nil then
        return wrapping_key
      end
      -- create target key; we will import encrypted target key in azure hsm key vault
      local target_key = create_target_key(input.key_name, input.source_group_id)
      if target_key.result == nil then
        return target_key
      end
      -- wrap wrapping key with kek key
      local wrapped_wrapping_key = wrap_wrapping_key(wrapping_key.result, config_kek_key_resp.result)
      if wrapped_wrapping_key.result == nil then
        return wrapped_wrapping_key
      end
      -- Wrap target key
      local wrapped_target_key = wrap_target_key(wrapping_key.result, target_key.result)
      if wrapped_target_key.result == nil then
        return wrapped_target_key
      end
      local byok = generate_byok(wrapped_wrapping_key.result, wrapped_target_key.result, input.kek_key_kid)
      local response = perform_byok(headers, byok, input.key_name, input.key_vault)
      -- Delete if non transient KEK and Wrapping keys were created
      if not is_transient then
        config_kek_key_resp.result:delete()
        wrapping_key.result:delete()
      end
      return response
    elseif input.operation == 'list' then
      return list_keys(headers, input.key_vault)
    elseif input.operation == 'delete' then
      if not is_valid_cloud_key(headers, input.key_vault, input.key_name) then
        return "Something went wrong or key does not exist in Azure cloud or in DSM."
      end
      return delete_key(headers, input.key_vault, input.key_name)
    elseif input.operation == 'restore' then
      if is_valid_cloud_key(headers, input.key_vault, input.key_name) then
        return "Cannot restore. Azure still has a key with this name"
      end
      return restore_key(headers, input.key_vault, input.key_name)
    else
      return {result = '', error = "Operation is not valid. Operation value should be one of `configure`, `create`, `list`, `delete` or `restore`."}
    end
  end
end
