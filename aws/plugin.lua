-- Name: AWS BYOK
-- Version: 1.0
-- Description:## Short Description
-- This plugin implements the Bring your own key (BYOK) model for AWS cloud. Using this plugin you can keep your key inside Fortanix Self-Defending KMS and use BYOK features of AWS KMS.
-- 
-- ### ## Introduction
-- 
-- The cloud services provide many advantages but the major disadvantage of cloud providers has been security because physically your data resides with the cloud provider. To keep data secure in a cloud provider environment, enterprises use encryption. So securing their encryption keys become significantly important. Bring Your Own Key (BYOK) allows enterprises to encrypt their data and retain control and management of their encryption keys. This plugin provides an implementation to use the AWS cloud BYOK model.
-- 
-- ## Requirenment
-- 
-- - Fortanix Self-Defending KMS Version >= 3.17.1330
-- 
-- ## Use cases
-- 
-- The plugin can be used to
-- 
-- - Push Fortanix Self-Defending KMS key in AWS KMS
-- - List Fortanix Self-Defending KMS AWS BYOK key
-- - Rotate Fortanix Self-Defending KMS AWS BYOK key
-- 
-- 
-- ## Setup
-- 
-- - Log in to AWS portal
-- - Create AWS IAM policy
-- - Create AWS KMS plicy
-- - Attach policy to IAM user
-- 
-- ## Input/Output JSON object format
-- 
-- ### Configure operation
-- 
-- This operation configures AWS IAM secret key and access key in Fortanix Self-Defending KMS and returns a UUID. You need to pass this UUID for other operations. This is a one time process.
-- 
-- #### Parameters 
-- 
-- * `operation`: The operation which you want to perform. A valid value is `configure`.
-- * `secret_key`: AWS secret key
-- * `access_key`: AWS access key
-- 
-- #### Example
-- 
-- Input JSON
-- ```
-- {
--   "operation": "configure",
--   "secret_key": "GZA....sz",
--   "access_key": "AK...ZCX"
-- }
-- ```
-- Output JSON
-- ```
-- {
--   "secret_id": "90cc4fdf-db92-4c52-83a5-ffaec726b224"
-- }
-- ```
-- 
-- ### Create operation
-- 
-- This operation will create an AES-256 key in Fortanix Self-Defending KMS and import it in AWS KMS.
-- 
-- #### Parameters 
-- 
-- * `operation`: The operation which you want to perform. A valid value is `create`.
-- * `name`: Name of the key
-- * `secret_id`: The response of `configuration` operation. 
-- 
-- #### Example
-- 
-- Input JSON
-- 
-- ```
-- {
--   "operation": "create", 
--   "name": "test-key",
--   "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
-- }
-- ```
-- 
-- Output JSON
-- ```
-- {
--   "key_size": 256,
--   "custom_metadata": {
--     "AWS_KEY_ID": "46fa7bfd-24de-4e5d-be94-99fa3e3bf09e"
--   },
--   "created_at": "20200725T155625Z",
--   "lastused_at": "19700101T000000Z",
--   "obj_type": "AES",
--   "never_exportable": false,
--   "state": "Active",
--   "acct_id": "15e5e446-c911-4ad4-92b4-85eabefabfe7",
--   "activation_date": "20200725T155625Z",
--   "creator": {
--     "plugin": "c2aa3055-5532-4ff2-8ca5-cb450c26e280"
--   },
--   "key_ops": [
--     "ENCRYPT",
--     "DECRYPT",
--     "EXPORT",
--     "APPMANAGEABLE"
--   ],
--   "enabled": true,
--   "origin": "FortanixHSM",
--   "kid": "04286b5c-4707-4ed1-bf92-934c7a077d5f",
--   "name": "test-key",
--   "public_only": false,
--   "group_id": "9564adfd-2399-46d0-90c0-4cf80b7bcc33",
--   "compliant_with_policies": true
-- }
-- ```
-- 
-- ### List operation
-- 
-- This operation will list all the BYOK keys from AWS.
-- 
-- #### Parameters 
-- 
-- * `operation`: The operation which you want to perform. A valid value is `list`.
-- * `secret_id`: The response of `configuration` operation. 
-- 
-- #### Example
-- 
-- Input JSON
-- ```
-- "
-- {
--   "operation": "list", 
--   "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
-- }
-- "
-- ```
-- 
-- Output JSON
-- ```
-- {
--   "KeyCount":1,
--   "Keys":[
--     {
--       "KeyArn":"arn:aws:kms:us-west-1:513076507034:key/46fa7bfd-24de-4e5d-be94-99fa3e3bf09e",
--       "KeyId":"46fa7bfd-24de-4e5d-be94-99fa3e3bf09e
--     }
--   ],
--   "Truncated\":false
-- }
-- ```
-- 
-- ### Rotate operation
-- 
-- This operation will rotate a key in Fortanix Self-Defending KMS as well as in AWS KMS key.
-- 
-- #### Parameters 
-- 
-- * `operation`: The operation which you want to perform. A valid value is `rotate`.
-- * `name`: Name of the key  
-- * `secret_id`: The response of `configuration` operation. 
-- 
-- #### Example
-- 
-- Input JSON
-- ```
-- {
--   "operation": "rotate", 
--   "name": "test-key",
--   "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
-- }
-- ```
-- 
-- Output JSON
-- ```
-- {
--   "obj_type": "AES",
--   "kid": "49521024-e28f-4f6c-82e7-a9f29088ec43",
--   "activation_date": "20200725T155809Z",
--   "lastused_at": "19700101T000000Z",
--   "compliant_with_policies": true,
--   "group_id": "9564adfd-2399-46d0-90c0-4cf80b7bcc33",
--   "enabled": true,
--   "acct_id": "15e5e446-c911-4ad4-92b4-85eabefabfe7",
--   "key_ops": [
--     "ENCRYPT",
--     "DECRYPT",
--     "EXPORT",
--     "APPMANAGEABLE"
--   ],
--   "origin": "FortanixHSM",
--   "created_at": "20200725T155809Z",
--   "key_size": 256,
--   "state": "Active",
--   "creator": {
--     "plugin": "c2aa3055-5532-4ff2-8ca5-cb450c26e280"
--   },
--   "never_exportable": false,
--   "custom_metadata": {
--     "AWS_KEY_ID": "129bfa49-3dde-4d5f-87f7-f883e80e7893"
--   },
--   "name": "test-key",
--   "public_only": false
-- }
-- ```
-- 
-- ### Release Notes
-- - Initial release

--[[
configure
{
  "operation": "configure",
  "secret_key": "GZA....sz",
  "access_key": "AK...ZCX"
}

create
{
  "operation": "create", 
  "name": "test-key",
  "secret_id": "d6807129-27fe-4f64-8509-f9d3326c1de5"
}

list
{
  "operation": "list",
  "secret_id": "d6807129-27fe-4f64-8509-f9d3326c1de5"
}

rotate
{
  "operation": "rotate", 
  "name": "test-key",
  "secret_id": "d6807129-27fe-4f64-8509-f9d3326c1de5"
}
--]]

function sign(key, msg) -- SHA256-HMAC
  assert(getmetatable(key) == Blob and type(msg) == 'string')

  local hmac_key = assert(Sobject.import { obj_type = 'HMAC', value = key, transient = true })
  return assert(hmac_key:mac { alg = 'SHA256', data = Blob.from_bytes(msg) }).digest
end

function getSignatureKey(key, dateStamp, regionName, serviceName)
  assert(type(key) == 'string' and type(dateStamp) == 'string' and type(regionName) == 'string' and type(serviceName) == 'string')

  local kDate = sign(Blob.from_bytes('AWS4' .. key), dateStamp)
  local kRegion = sign(kDate, regionName)
  local kService = sign(kRegion, serviceName)
  return sign(kService, 'aws4_request')
end

-- ported from https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
function aws_request(secret_id, amzTarget, request_body, method)
  local service = 'kms'
  local host = 'kms.us-west-1.amazonaws.com'
  local region = 'us-west-1'
  local endpoint = 'https://kms.us-west-1.amazonaws.com'
  local sobject, err = Sobject { id = secret_id }
  if sobject == nil or err ~= nil then
    err = "AWS credential is not configured or incorrect. Please run cofigure operation."
    return nil, err
  end
  if sobject.custom_metadata == nil then
      err = "AWS credential is not configured or incorrect. Please run cofigure operation."
    return nil, err
  end
  if sobject.custom_metadata["AccessKey"] == nil then
     err = "AWS credential is not configured or incorrect. Please run cofigure operation."
    return nil, err
  end
  local access_key = sobject.custom_metadata['AccessKey']
  local secret_key = sobject:export().value:bytes()

  -- FIXME there should be a better way to get the current date/time
  local amzdate = (Sobject.create { obj_type = 'AES', key_size = 128, transient = true }).created_at

  local datestamp = amzdate:sub(1, 8)
  local content_type = 'application/x-amz-json-1.1'
  local canonical_uri = '/'
  local canonical_querystring = ''
  local canonical_headers = 'content-type:' .. content_type .. '\n' .. 'host:' .. host .. '\n' .. 'x-amz-date:' .. amzdate .. '\n' .. 'x-amz-target:' .. amzTarget .. '\n'
  local signed_headers = 'content-type;host;x-amz-date;x-amz-target'
  local payload_hash = digest { alg = 'SHA256', data = Blob.from_bytes(request_body) }.digest:hex():lower()
  local canonical_request = method .. '\n' .. canonical_uri .. '\n' .. canonical_querystring .. '\n' .. canonical_headers .. '\n' .. signed_headers .. '\n' .. payload_hash

  local algorithm = 'AWS4-HMAC-SHA256'
  local credential_scope = datestamp .. '/' .. region .. '/' .. service .. '/' .. 'aws4_request'
  local string_to_sign = algorithm .. '\n' .. amzdate .. '\n' .. credential_scope .. '\n' .. digest { alg = 'SHA256', data = Blob.from_bytes(canonical_request) }.digest:hex():lower()

  local signing_key = getSignatureKey(secret_key, datestamp, region, service)
  local signature = sign(signing_key, string_to_sign):hex():lower()
  
  local authorization_header = algorithm .. ' ' .. 'Credential=' .. access_key .. '/' .. credential_scope .. ', ' .. 'SignedHeaders=' .. signed_headers .. ', ' .. 'Signature=' .. signature
  local headers = { ['x-amz-date'] = amzdate, ['X-Amz-Target'] = amzTarget, ['Content-Type'] = content_type, ['Authorization'] = authorization_header}
  local request_url = endpoint .. '?' .. canonical_querystring
  
  response, err = request { method = method, url = request_url, headers = headers, body=request_body }
  if response.status ~= 200 then
    return nil, response
  end
  return json.decode(response.body), err
end

function aws_list_keys(secret_id)
  local response, err = aws_request(secret_id ,"TrentService.ListKeys", "{}", "POST")
  if response ~= nil then
    return response, nil
  end
  return response, err
end

function aws_create_key(secret_id, name)
  request_body = '{"CustomerMasterKeySpec": "SYMMETRIC_DEFAULT","Origin": "EXTERNAL", "Description": "' .. name .. '"}'
  local response, err = aws_request(secret_id, "TrentService.CreateKey", request_body, "POST")
  if response ~= nil  then
   -- local response_json = json.decode(response)
    return response.KeyMetadata.KeyId, nil      
  end
  return response, err   
end

function aws_delete_key(secret_id, aws_key_id)
  request_body = '{"KeyId": "' .. aws_key_id .. '"}'
  response, err = aws_request(secret_id, "TrentService.ScheduleKeyDeletion", request_body, "POST")
  return response, err   
end

function aws_get_import_params(secret_id, key_id)
  local request = { KeyId = key_id, WrappingAlgorithm = "RSAES_OAEP_SHA_256", WrappingKeySpec = "RSA_2048"}
  local response, err = aws_request(secret_id, "TrentService.GetParametersForImport", json.encode(request), "POST")
  return response, err
end

function aws_import_key(secret_id, key_id, wrapped_key, import_params)
  local request = { KeyId = key_id, ExpirationModel = "KEY_MATERIAL_DOES_NOT_EXPIRE", ImportToken = import_params.ImportToken, EncryptedKeyMaterial = wrapped_key}
  local response, err = aws_request(secret_id, "TrentService.ImportKeyMaterial", json.encode(request), "POST")
  return response, err
end

function wrap_key_for_import(secret_id, key_id, master_key, import_params)
  -- import AWS Public key
  local pubkey = assert(Sobject.import { obj_type = 'RSA', transient = true, value = Blob.from_base64(import_params.PublicKey)})
  -- Wrap master key with Pub Key
  wrap_response = assert(pubkey:wrap { subject = master_key, mode = 'OAEP_MGF1_SHA256' })
  return wrap_response.wrapped_key:base64()
end

function create_alias(secret_id, key_id, name)
  local request = { TargetKeyId = key_id, AliasName = 'alias/sdkms/' .. name}
  local response, err = aws_request(secret_id, "TrentService.CreateAlias", json.encode(request), "POST")
 return response, err  
end

function update_alias(secret_id, key_id, name)
  local request = { TargetKeyId = key_id, AliasName = 'alias/sdkms/' .. name}
  local response, err = aws_request(secret_id, "TrentService.UpdateAlias", json.encode(request), "POST")
  return response, err
end

function run(input)
  if input.operation == "configure" then
    local name = Blob.random { bits = 64 }:hex()
    local secret = assert(Sobject.import{ name = name, obj_type = "SECRET", value = Blob.from_bytes(input.secret_key), custom_metadata = {["AccessKey"] = input.access_key }})
    return {secret_id = secret.kid}
    
  elseif input.operation == "list" then
    keys, err = aws_list_keys(input.secret_id)
    return keys, err
    
  elseif input.operation == "create" then
    -- Create master key in SDKMS
    local master_key = assert(Sobject.create { obj_type = 'AES', key_size = 256, name = input.name, key_ops = {'ENCRYPT', 'DECRYPT', 'APPMANAGEABLE', 'EXPORT'}})
  
    -- Wrap master key with AWS public key
    local aws_key_id, err = aws_create_key(input.secret_id, input.name)
    if aws_key_id == nil then
      master_key:delete()
      return { result = aws_key_id, error = err, message = "create BYOK key operation fail"}
    end
    local import_params, err = aws_get_import_params(input.secret_id, aws_key_id)
    if import_params == nil then
      master_key:delete()
      aws_delete_key(input.secret_id, aws_key_id)
     return {result = import_params, error = err, message = "create BYOK key operation fail"}
    end
    local wrapped_key = wrap_key_for_import(input.secret_id, aws_key_id, master_key, import_params)
    
    -- Import the wrapped key
    local resp, err = aws_import_key(input.secret_id, aws_key_id, wrapped_key, import_params)
    if resp == nil then
      master_key:delete()
      aws_delete_key(input.secret_id, aws_key_id)
      return {result = resp, error = err, message = "create BYOK key operation fail"}
    end
    local resp, err = create_alias(input.secret_id, aws_key_id, input.name)
    if err ~= nil then
      master_key:delete()
      -- delete CMK
      aws_delete_key(input.secret_id, aws_key_id)
      return {result = resp, error = err, message = "create BYOK key operation fail"}
    end
    -- Update the master key custom metadata
    master_key:update{custom_metadata = { AWS_KEY_ID = aws_key_id}}
    return Sobject {name = input.name}
 
  elseif input.operation == "rotate" then
    -- Rotate master key in SDKMS
    local new_master_key = assert(Sobject.create { obj_type = 'AES', key_size = 256, name = 'new-' .. input.name, key_ops = {'ENCRYPT', 'DECRYPT', 'APPMANAGEABLE', 'EXPORT'}})
    local master_key = assert(Sobject { name = input.name })
    
    -- Wrap master key with AWS public key
    aws_key_id, err = aws_create_key(input.secret_id, input.name)
    if aws_key_id == nil then
      new_master_key:delete()
      return { result = aws_key_id, error = err, message = "rotate BYOK key operation fail"}
    end
    import_params, err = aws_get_import_params(input.secret_id, aws_key_id)
    if import_params == nil then
      new_master_key:delete()
      aws_delete_key(input.secret_id, aws_key_id)
      return {result = import_params, error = err, message = "rotate BYOK key operation fail"}
    end
    local wrapped_key = wrap_key_for_import(input.secret_id, aws_key_id, new_master_key, import_params)
    
    -- Import the wrapped key
    local resp, err = aws_import_key(input.secret_id, aws_key_id, wrapped_key, import_params)
    if resp == nil then
      new_master_key:delete()
      aws_delete_key(input.secret_id, aws_key_id)
      return {result = resp, error = err, message = "rotate BYOK key operation fail"}
    end
    update_alias(input.secret_id, aws_key_id, input.name)
    
    -- Update the master key custom metadata
    master_key:update { name = input.name .. '-replaced-by-' .. new_master_key.kid }
    new_master_key:update{custom_metadata = { AWS_KEY_ID = aws_key_id}}
    new_master_key:update { name = input.name }
    return Sobject {name = input.name} 
  end
end
