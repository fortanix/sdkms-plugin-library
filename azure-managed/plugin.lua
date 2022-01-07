-- Name: Self-Defending KMS-Azure Bring Your Own Key (BYOK) Managed HSM
-- Version: 1.1
-- Description: This plugin implements the Bring your own key (BYOK) HSM model for Azure managed HSMs. Using this plugin you can keep your key inside Fortanix DSM and use BYOK features of Azure managed HSM.
-- ## Introduction
-- 
-- The cloud services provide many advantages but the major disadvantage of cloud providers has been security because physically your data resides with the cloud provider. To keep data secure in a cloud provider environment, enterprises use encryption. So securing their encryption keys become significantly important. Bring Your Own Key (BYOK) allows enterprises to encrypt their data and retain control and management of their encryption keys. This plugin provides an implementation to use the Azure cloud BYOK model.
-- 
-- ## Requirenment
-- 
-- - Fortanix DSM Version >= 3.17.1330
-- 
-- ## Use cases
-- 
-- The plugin can be used to
-- 
-- - Push Fortanix DSM key in Azure managed HSM key vault
-- - List Azure BYOK keys
-- - Delete key in Fortanix DSM and corresponding key in Azure managed HSM
-- 
-- ## Setup
-- 
-- - Log in to https://portal.azure.com/
-- - Register an app in Azure cloud (Note down the Application (client) ID, Directory (tenant) ID, and client secret of this app). We will configure this information in Fortanix DSM
-- - Create a managed Azure key vault
-- - Add the above app in the `Access Policy` of the above key vault
-- - Create KEK key in Azure key vault
-- 
-- ```
-- az keyvault key create --kty RSA-HSM --size 2048 --name <KEY-NAME> --ops import --hsm-name <KEY-VAULT-NAME>
-- ```
-- 
-- ## Input/Output JSON object format
-- 
-- ### Configure operation
-- 
-- This operation configures Azure app credential in Fortanix DSM and returns a UUID. You need to pass this UUID for other operations. This is a one time process.
-- 
-- * `operation`: The operation which you want to perform. A valid value is `configure`.
-- * `tenant_id`: Azure tenant ID
-- * `client_id`: Azure app ID or client ID
-- * `client_secret`: Azure app secret
-- 
-- #### Example
-- 
-- Input JSON
-- ```
-- {
--    "operation": "configure",
--    "tenant_id": "de7becae...88ae6",
--    "client_id": "f8d7741...6abb6",
--    "client_secret": "SvU...5"
-- }
-- ```
-- 
-- Output JSON
-- ```
-- {
--   "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
-- }
-- ```
-- 
-- ### create operation
-- 
-- This operation will create an RSA key in Fortanix DSM and import it in Azure key vault.
-- 
-- #### Parameters
-- 
-- * `operation`: The operation which you want to perform. A valid value is `create`
-- * `key_name`: Name of the key
-- * `key_type`: The type of key required
-- * `key_size`: Required key size, in bits
-- * `key_vault`: Azure key vault name
-- * `kek_key_kid`: Azure Key Exchange Key (KEK) ID
-- * `secret_id`: The response of `configuration` operation.
-- 
-- Input JSON
-- ```
-- {
--   "operation": "create",
--   "key_name": "test-key",
--   "key_type": "RSA",
--   "key_size": 2048,
--   "key_vault": "test-hsm-keyvault",
--   "kek_key_kid": "https://test-hsm-keyvault.vault.azure.net/keys/test-kek-key/0ffc59a57f664b9fbde6455bd0ed5dd5",
--   "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
-- }
-- ```
-- 
-- Output JSON
-- ```
-- {
--   "result": {
--     "key": {
--       "n": "5FshKQ_5peJfFcer18EylSxbK94UErV0we_Z-v2EsTjcH_HZBWAUbAF0QJ_q0Qzy6nHA-u0DkAf63YTe3BhuUEU80Qek_pmZjfek4rgE53eSbrEqH7bYVxUEKSye3J_7oR-MMs4YkNqvyenBuLSv7QXZIcPu17zsNhIQrsv0MBdwV_QlewW9QQUeTPLbHUBV7m-r1gdffiINoRcGY9QvHb6dJphoOaNSzddUXm6Y21R7pwI2Lzo3MuEe2nwtOC-z_MW8jdsDNYxua4CipiGOe2Cqqg_wXsZcjpefzYqSGky2y3j7OoG1uHsafRqWatWTj_CHUPr-oII_r2_sGcxBrw",
--       "key_ops": [
--         "encrypt",
--         "decrypt",
--         "sign",
--         "verify",
--         "wrapKey",
--         "unwrapKey"
--       ],
--       "e": "AAEAAQ",
--       "kty": "RSA-HSM",
--       "kid": "https://test-hsm-keyvault.vault.azure.net/keys/test-key/21dc7692b9184c1ba8e643db8b142356"
--     },
--     "attributes": {
--       "recoveryLevel": "Recoverable+Purgeable",
--       "enabled": true,
--       "updated": 1593584773,
--       "created": 1593584773
--     }
--   }
-- ```
-- 
-- #### List Key operation
-- 
-- This operation will list all the BYOK keys from azure.
-- 
-- #### Parameters
-- 
-- * `operation`: The operation which you want to perform. A valid value is `list`.
-- * `key_name`: Name of the key
-- * `key_vault`: Azure key vault name
-- * `secret_id`: The response of `configuration` operation.
-- 
-- #### Example
-- 
-- Input JSON
-- ```
-- {
--   "operation": "list",
--   "key_vault": "test-hsm-keyvault",
--   "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
-- }
-- ```
-- 
-- Output JSON
-- ```
-- {
--   "result": {
--     "value": [
--       {
--         "attributes": {
--           "recoveryLevel": "Recoverable+Purgeable",
--           "enabled": true,
--           "updated": 1593587162,
--           "created": 1593587161,
--           "exp": 1596240000
--         },
--         "kid": "https://test-hsm-keyvault.vault.azure.net/keys/test-key",
--         "tags": {
--           "KMS": "SDKMS",
--           "KeyType": "BYOK"
--         }
--       }
--     ],
--     "nextLink": null
--   }
-- }
-- ```
-- 
-- ### Delete Key operation
-- 
-- This operation will delete a key in Fortanix DSM as well as Azure key vault.
-- 
-- #### Parameters
-- 
-- * `operation`: The operation which you want to perform. A valid value is `delete`.
-- * `key_name`: Name of the key
-- * `key_vault`: Azure key vault name
-- * `secret_id`: The response of `configuration` operation.
-- 
-- Input JSON
-- ```
-- {
--   "operation": "delete",
--   "key_name": "test-key",
--   "key_vault": "test-hsm-keyvault",
--   "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
-- }
-- ```
-- 
-- Output JSON
-- ```
-- {
--   "result": {
--     "scheduledPurgeDate": 1601363625,
--     "tags": {
--       "KMS": "SDKMS",
--       "KeyType": "BYOK"
--     },
--     "deletedDate": 1593587625,
--     "key": {
--       "kid": "https://test-hsm-keyvault.vault.azure.net/keys/test-key/e71e5af81eaa4cbd85674d8b7a76d065",
--       "n": "AL2b7tdZzZugFJI3mRS39h_6x9hh4XKJ3W3UrbwFtA9bZ7kEfGWIyE1IJWQX5KGkW26WkYiAABvx1bU4J7lO1TFkVjvHYRr5cC5eAySBGC1yaxrZ-3SguE7R33EF54ja3doeqapnkCM6GK2RuhIsT4Spz3cm9P0dfknz3DapON-7",
--       "kty": "RSA",
--       "e": "AQAB",
--       "key_ops": [
--         "encrypt",
--         "decrypt",
--         "sign",
--         "verify",
--         "wrapKey",
--         "unwrapKey"
--       ]
--     },
--     "attributes": {
--       "enabled": true,
--       "recoveryLevel": "Recoverable+Purgeable",
--       "created": 1593587492,
--       "updated": 1593587492
--     },
--     "recoveryId": "https://test-hsm-keyvault.vault.azure.net/deletedkeys/test-key"
--   }
-- }
-- ```
-- 
-- ## References
-- - [Azure HSM BYOK](https://docs.microsoft.com/en-us/azure/key-vault/keys/hsm-protected-keys)
-- 
-- ## Release Notes
--  Initial release
--
-- ## Release Notes
-- - Better error handling

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
  "key_type": "RSA",
  "key_size": 2048,
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
function save_credentials(tenant_id, client_id, client_secret)
  local name = Blob.random { bits = 64 }:hex()
  local secret, err = Sobject.import{ name = name, obj_type = 'SECRET', value = Blob.from_bytes(client_secret), custom_metadata = {['TenantId'] = tenant_id, ['ClientId'] = client_id }}
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
  local request_body = 'grant_type=client_credentials&client_id='..client_id..'&client_secret='..client_secret..'&resource=https%3A%2F%2Fmanagedhsm.azure.net'
  local response = request { method = 'POST', url = url, headers = headers, body=request_body }
  if response.status ~= 200 then
    return {result = nil, error = json.decode(response.body)}
  end
  return {result = json.decode(response.body).access_token, error = nil}
end
function config_kek_key(headers, kek_key_kid)
  -- TODO: Remove hardcoded values
  -- only work for 2048 kek key
  local prefix = '30820122300D06092A864886F70D01010105000382010F003082010A02820101'
  local suffix = '0203010001'
  local url = kek_key_kid .. '?api-version=7.0'
  local response = request { method = 'GET' , url = url, headers = headers, body='' }
  if response.status ~= 200 then
    return {result = nil, error = response}
  end
  local json_resp = json.decode(response.body)
  local modulus = json_resp['key']['n']
  local name = Blob.random { bits = 64 }:hex()
  local encoded_kek_key = prefix ..  prepad_signed(Blob.from_base64(modulus):hex()) ..suffix
  local sobject, err = Sobject.import { name = name, obj_type = 'RSA', value = Blob.from_hex(encoded_kek_key), key_ops = {'EXPORT', 'WRAPKEY'}, transient = true }
  if sobject == nil then
    err.message = err.message .. '. Failed to import KEK in DSM.'
    return {result = nil, error = err}
  end
  return {result = sobject, error = nil}
end
function create_wrapping_key()
  local name = Blob.random { bits = 64 }:hex()
  local sobject, err = Sobject.create { name = name, obj_type = 'AES', key_size = 256, key_ops = {'EXPORT', 'WRAPKEY'}, transient = true}
  if sobject == nil then
    err.message = err.message .. '. Failed to create wrapping key in DSM.'
    return {result = nil, error = err}
  end
  return {result = sobject, error = nil}
end
function create_target_key(name, key_type, key_size)
  local sobject, err = Sobject.create { name = name, obj_type = key_type, key_size = key_size, key_ops = {'EXPORT'}}
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
function wrap_target_key(wrapping_key, target_key, target_key_type)
  local wrap_response, err
  if target_key_type == "RSA" then
    wrap_response, err = wrapping_key:wrap { subject = target_key, mode = 'KWP', alg = 'AES', key_format = 'Pkcs8' }
  else
    wrap_response, err = wrapping_key:wrap { subject = target_key, mode = 'KWP', alg = 'AES'}
  end

  if wrap_response == nil then
    err.message = err.message .. '. Failed to wrap target key.'
    return nil, err
  end
  return {result = wrap_response.wrapped_key:bytes(), error = nil}
end
function generate_byok(wrapped_wrapping_key, wrapped_target_key, kek_key_kid)
    local header = {
        kid = kek_key_kid,
        alg = "dir",
        enc = "CKM_RSA_AES_KEY_WRAP"
    }
    local generator = TOOL_NAME .. ", Version : " .. TOOL_VERSION .. "; Fortanix Self-Defending KMS, Firmware version : " .. FIRMWARE_VERSION
    local ciphertext = base64url_encode(wrapped_wrapping_key .. wrapped_target_key)
    local byok = {
        schema_version = SCHEMA_VERSION,
        header = header,
        ciphertext = ciphertext,
        generator = generator
    }
    return byok
end
function perform_byok(headers, byok, name, key_vault, target_key_kty)
    local url = "https://" .. key_vault .. ".managedhsm.azure.net/keys/" .. name .. "?api-version=7.0"
    local b64 = json.encode(byok)
    local body = {
        key = {
            kty = target_key_kty,
            key_hsm = Blob.from_bytes(b64):base64(),
        }
    }
    local response, err = request { method = "PUT", url = url, headers = headers, body = json.encode(body) }
    if response.status ~= 200 then
        return { result = nil, error = response, body = body }
    end
    -- Update target key
    sobject = Sobject { name = name }
    sobject:update{custom_metadata = { AZURE_KEY_ID = json.decode(response.body).key.kid}}
    return {result = json.decode(response.body), error = nil}
end
function list_keys(headers, key_vault)
  local url = 'https://'.. key_vault ..'.managedhsm.azure.net/keys?api-version=7.0'
  local response, err = request { method = 'GET', url = url, headers = headers, body='' }
  if err ~=nil or response.status ~= 200 then
    return {result = response, error = err, message = "Something went wrong. Can't list the keys."}
  end
  return {result = json.decode(response.body), error = nil}
end
function delete_key(headers, key_vault, key_name)
  local url = 'https://'.. key_vault ..'.managedhsm.azure.net/keys/'.. key_name ..'?api-version=7.0'
  local response = request { method = 'DELETE', url = url, headers = headers, body='' }
  if err ~=nil or response.status ~= 200 then
    return {result = response, error = err, message = "Something went wrong. Can't delete the key."}
  end
  return {result = json.decode(response.body), error = nil}
end
function is_valid(operation)
  local opr = {'configure', 'create', 'delete', 'list'}
  for i=1,#opr do
    if opr[i] == operation then
      return true
    end
  end
  return false
end
function is_valid_sdkms_key(name)
  local response1, err1 = Sobject {name = name}
  if err1 ~=nil or response1 == nil then
    return false
  end
  return true
end
function is_valid_cloud_key(headers, key_vault, name)
  url = 'https://'.. key_vault ..'.managedhsm.azure.net/keys/'..name..'?api-version=7.0'
  local response2, err2 = request {method = 'GET', url = url, headers = headers, body = ''}
  if err2 ~= nil or response2.status ~= 200 then
    return false
  end
  return true
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
  elseif input.operation == 'create' then
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
    return {result = nil, error = "Operation is not valid. Operation value should be one of `configure`, `create`, `list`, or `delete`."}
  end

  if input.operation == 'configure' then
    return save_credentials(input.tenant_id, input.client_id, input.client_secret)
  else
    local resp, err, message = login(input.secret_id)
    if resp.result == nil then
      return {result = resp, error = err, message = message}
    end
    local authorization_header = 'Bearer ' ..resp.result
    headers = {['Content-Type'] = 'application/json', ['Authorization'] = authorization_header}
    if input.operation == 'create' then
      if is_valid_cloud_key(headers, input.key_vault, input.key_name) then
        return "Something went wrong, or the key already exists in Azure cloud."
      end
      if is_valid_sdkms_key(input.key_name) then
        return "Something went wrong, or the key already exists in DSM."
      end
      local config_kek_key_resp = config_kek_key(headers, input.kek_key_kid)
      if config_kek_key_resp.result == nil then
        return config_kek_key_resp
      end
      -- create wrapping key used to wrap target key
      local wrapping_key = create_wrapping_key()
      if wrapping_key.result == nil then
        return wrapping_key
      end
      -- create taget key; we will import encrypted taget key in azure hsm key vault
      local target_key = create_target_key(input.key_name, input.key_type, input.key_size)
      if target_key.result == nil then
        return target_key
      end
      -- wrap wrapping key with kek key
      local wrapped_wrapping_key = wrap_wrapping_key(wrapping_key.result, config_kek_key_resp.result)
      if wrapped_wrapping_key.result == nil then
        return wrapped_wrapping_key
      end
      -- Wrap target key
      local wrapped_target_key = wrap_target_key(wrapping_key.result, target_key.result, input.key_type)
      if wrapped_target_key.result == nil then
        return wrapped_target_key
      end
      local byok = generate_byok(wrapped_wrapping_key.result, wrapped_target_key.result, input.kek_key_kid)
      local target_key_kty = input.key_type .. "-HSM"
      if input.key_type == "AES" then
        target_key_kty = "oct-HSM"
      end
      local response = perform_byok(headers, byok, input.key_name, input.key_vault, target_key_kty)
      return response
    elseif input.operation == 'list' then
      return list_keys(headers, input.key_vault)
    elseif input.operation == 'delete' then
      if not is_valid_cloud_key(headers, input.key_vault, input.key_name) then
        return "Something went wrong, or the key does not exist in Azure cloud or in DSM."
      end
      return delete_key(headers, input.key_vault, input.key_name)
    else
      return {result = '', error = "Operation is not valid. Operation value should be one of `configure`, `create`, `list`, or `delete`."}
    end
  end
end
