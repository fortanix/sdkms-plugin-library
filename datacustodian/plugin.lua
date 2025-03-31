--[[
configure operation
{
   "operation": "configure",
   "base_url": "https://api-kms-v2-preprod.datacustodian.cloud.sap",
   "api_key": "de7becae...88ae6",
   "secret": "SvU...5"
}

import operation
{
  "operation": "import",
  "secret_id": "75803498-b97f-430e-8fd3-bfd995ffe958",
  "is_exportable": false,
  "datacustodian_role": "SAC_MASTER_KEY",
  "datacustodian_group_id": "5069b28d-a01c-4bc0-97ce-c19064d056c0",
  "target_key_type" : "RSA",
  "target_key_name": "test-key",
  "target_key_description": "This is a test key for BYOK from DSM",
  "target_key_size": 2048,
  "target_key_operations": [ "ENCRYPT", "DECRYPT", "SIGN", "VERIFY", "WRAP", "UNWRAP" ],
  "kek_key_id": "a105bd21-57cd-4a8a-9a1d-4bf1b1022ab3",
  "kek_key_version": 0
}

rotate operation
{
  "operation": "rotate",
  "secret_id": "2b4a35dc-511d-4d1c-ad30-29e57cae7686",
  "datacustodian_key_id": "2504681e-cfd2-44ee-ad63-66211560cc62",
  "datacustodian_group_id": "5069b28d-a01c-4bc0-97ce-c19064d056c0",
  "target_key_name": "test-imported-key-20220517-aes-01",
  "kek_key_id": "a58860d9-e832-433d-9c33-d310dd201adc",
  "kek_key_version": 0
}

For AWS KMS provider import and rotate operations, please refer to the README.
]]--

function configure_credentials(api_key, secret, base_url)
  local request_body = json.encode({apiKey = api_key, secret = secret})
  local url = base_url .. '/kms/v2/auth/credentialActivate'
  local headers = { ['Content-Type'] = 'application/json', ['accept'] = 'application/json'}
  local response, err = request { method = 'PUT', url = url, headers = headers, body=request_body }
  if err ~= nil then
    return {result = nil, error = err}
  end
  if response.status ~= 200 then
    decoded_body = json.decode(response.body)
    response.body = decoded_body
    return {result = nil, error = response}
  end
  local json_resp = json.decode(response.body);
  local secret = json_resp['secret']
  if secret == nil then
    return {result = nil, error = 'Failed to refresh the secret in the configure operation'}
  end
  local name = Blob.random { bits = 64 }:hex()
  local secret, err = Sobject.import{ name = name, obj_type = 'SECRET', value = Blob.from_bytes(secret), custom_metadata = {['api_key'] = api_key, ['base_url'] = base_url }}
  if secret == nil then
    err.message = err.message .. '. Failed to configure Data Custodian credentials'
    return {secret_id = nil, error = err}
  end
  return {secret_id = secret.kid, error = nil}
end

function login(secret_id)
  local sobject, err = Sobject { id = secret_id }
  if sobject == nil then
    return {result = nil, error = err, message = "Data Custodian credentials are not configured, or invalid. Please run configure operation."}
  end
  if sobject.custom_metadata == nil then
    return {result = nil, error = err, message = "Data Custodian credentials are not configured, or invalid. Please run configure operation."}
  end
  if sobject.custom_metadata['api_key'] == nil or sobject.custom_metadata['base_url'] == nil then
    return {result = nil, error = err, message = "Data Custodian credentials are not configured, or invalid. Please run configure operation."}
  end
  local secret = sobject:export().value:bytes()
  local api_key = sobject.custom_metadata['api_key']
  local base_url = sobject.custom_metadata['base_url']
  local headers = { ['Content-Type'] = 'application/json', ['accept'] = 'application/json'}
  local url = base_url .. '/kms/v2/auth/request'

  local request_body = json.encode({ apiKey = api_key, secret = secret })
  local response, err = request { method = 'POST', url = url, headers = headers, body=request_body }
  if err ~= nil then
    return {result = nil, error = err}
  end
  if response.status ~= 200 then
    decoded_body = json.decode(response.body)
    response.body = decoded_body
    return {result = nil, error = response}
  end
  return {result = json.decode(response.body).accessToken, error = nil}
end

function config_kek_key(headers, base_url, target_key_id, is_aws_key_store, input, is_transient)

  local response, err, json_resp, kek_key_id = nil
  local wrapping_algorithm = 'RSA_AES_WRAP_SHA256'
  if input.target_key_type == 'AES' then
    wrapping_algorithm = 'OAEP_MGF1_SHA256'
  end

  local request_body
  local url = base_url .. '/kms/v2/keys'
  
  if is_aws_key_store == true then
    --if rotate operation then refresh the public key component of the wrapper key
    if input.operation == 'rotate' then
      local url = base_url .. '/kms/v2/keys/' .. input.kek_key_id .. '/versions'
      response, err = request{method = 'POST' , url = url, headers = headers, body=''}
    else
      request_body = json.encode({
        targetKeyId = target_key_id,
        size = input.kek_key_size,
        wrappingAlgorithm = wrapping_algorithm
      })
      response, err = request{method = 'POST' , url = url, headers = headers, body=request_body}
    end

    if err ~= nil then
      return {result = nil, kek_id = nil, error = err}
    end
    if response.status ~= 201 then
      decoded_body = json.decode(response.body)
      response.body = decoded_body
      return {result = nil, kek_id = nil, error = response}
    end
    json_resp = json.decode(response.body)

    --Fetch the KEK if the target keystore is AWS
    if input.operation == 'rotate' then
      local kek_key_version = json_resp['version']
      if kek_key_version == nil then 
        return {result = nil, kek_id = nil, error = 'Failed to obtain the version of the KEK for the target key in AWS Provider for rotate operation'}
      end
      url = base_url .. '/kms/v2/keys/' .. input.kek_key_id .. '/versions/' .. kek_key_version .. '/publicKey?outputFormat=BASE64_DER'
    else 
      kek_key_id = json_resp['id']
      if kek_key_id == nil then 
        return {result = nil, kek_id = nil, error = 'Failed to obtain the id of the KEK for the target key in AWS Provider for import operation'}
      end
      url = base_url .. '/kms/v2/keys/' .. kek_key_id .. '/versions/' .. '0' .. '/publicKey?outputFormat=BASE64_DER'
    end 
    response, err = request { method = 'GET' , url = url, headers = headers, body='' }
  else
    --Fetch the KEK
    local url = base_url .. '/kms/v2/keys/' .. input.kek_key_id .. '/versions/' .. input.kek_key_version .. '/publicKey?outputFormat=BASE64_DER'
    response, err = request { method = 'GET' , url = url, headers = headers, body='' }
  end 

  if err ~= nil then
    return {result = nil, kek_id = nil, error = err}
  end
  if response.status ~= 200 then
    decoded_body = json.decode(response.body)
    response.body = decoded_body
    return {result = nil, kek_id = nil, error = response}
  end
  local json_resp = json.decode(response.body)
  local kek_value = json_resp['publicKey']

  -- Import KEK into DSM
  local name = Blob.random { bits = 64 }:hex()
  local sobject, err = Sobject.import { name = name, obj_type = 'RSA', value = kek_value, key_ops = {'EXPORT', 'WRAPKEY'}, transient = is_transient }
  if sobject == nil then
    err.message = err.message .. '. Failed to import KEK key in DSM.'
    return {result = nil, kek_id = nil, error = err}
  end
  return {result = sobject, kek_key_id = kek_key_id, error = nil}
end

function create_wrapping_key(is_transient)
  local name = Blob.random { bits = 64 }:hex()
  local sobject, err = Sobject.create { name = name, obj_type = 'AES', key_size = 256, key_ops = {'EXPORT', 'WRAPKEY'}, transient = is_transient}
  if sobject == nil then
    err.message = err.message .. '. Failed to create wrapping key in DSM.'
    return {result = nil, error = err}
  end
  return {result = sobject, error = nil}
end

function create_target_key(headers, base_url, is_aws_key_store, input)
  local response, err,target_key_id = nil
  
  if is_aws_key_store == true then
    --Create target key in DCKMS AWS Keystore with import enabled
    local url = base_url .. '/kms/v2/keys'
    local request_body
    request_body = json.encode({ 
          name = input.target_key_name,
          description = input.target_key_description,
          groupId = input.datacustodian_group_id,
          enabled = false,
          imported = true,
          operations = input.target_key_operations,
          type = input.target_key_type,
          size = input.target_key_size,
          role = input.datacustodian_role
    })
    response, err = request { method = 'POST' , url = url, headers = headers, body=request_body }
    if err ~= nil then
      return {result = nil, error = err}
    end
    if response.status ~= 201 then
      decoded_body = json.decode(response.body)
      response.body = decoded_body
      return {result = nil, error = response}
    end

    local json_resp = json.decode(response.body)
    target_key_id = json_resp['id']
  end

  local sobject = Sobject { name = input.target_key_name }
  if sobject ~= nil then
    return {result = sobject, error = nil}
  end
  local sobject, err = Sobject.create { 
    name = input.target_key_name, 
    obj_type = input.target_key_type, 
    key_size = input.target_key_size, 
    key_ops = {'EXPORT'}
  }
  if sobject == nil then
    err.message = err.message .. '. Failed to create target key in DSM.'
    return {result = nil, error = err}
  end
  return {result = sobject, target_key_id = target_key_id,  error = nil}
end

function rotate_target_key(name)
  local sobject = Sobject { name = name }
  if sobject == nil then
    err.message = err.message .. '. Failed to rotate target key in DSM. It does not exist'
    return {result = nil, error = err}
  end
  -- local sobject, err = sobject:rekey { name = name, obj_type = key_type, key_size = key_size, key_ops = {'EXPORT'} }
  local sobject, err = sobject:rekey { name = name, key_ops = {'EXPORT'} }
  if sobject == nil then
    err.message = err.message .. '. Failed to rotate target key in DSM.'
    return {result = nil, error = err}
  end
  return {result = sobject, error = nil}
end

function wrap_rsa(wrapping_key, target_key)
  local wrap_response, err = wrapping_key:wrap { subject = target_key, mode = 'OAEP_MGF1_SHA256', alg = 'RSA'}
  if wrap_response == nil then
    err.message = err.message .. '. Failed to wrap key : ' .. target_key.name .. ' with wrapping key ' .. wrapped_key.name
    return {result = nil, error = err}
  end
  return {result = wrap_response.wrapped_key:bytes(), error = nil}
end

function wrap_aes(wrapping_key, target_key)
  local wrap_response, err = wrapping_key:wrap { subject = target_key, mode = 'KWP', alg = 'AES', key_format = 'Pkcs8' }
  if wrap_response == nil then
    err.message = err.message .. '. Failed to wrap key : ' .. target_key.name .. ' with wrapping key ' .. wrapping_key.name
    return {result = nil, error = err}
  end
  return {result = wrap_response.wrapped_key:bytes(), error = nil}
end

function get_wrapped_byok_value(target_key_type, wrapped_wrapping_key, wrapped_target_key)
  local byok_value
  if target_key_type == 'RSA' then
    byok_value = Blob.from_bytes(wrapped_wrapping_key.result .. wrapped_target_key.result):base64()
  elseif target_key_type == 'AES' then
    byok_value = Blob.from_bytes(wrapped_target_key.result):base64()
  end
  return byok_value
end

function perform_byok(headers, base_url, wrapped_key_value, target_key_id, kek_key_id, is_aws_key_store, input)
  local key_operations
  if input.target_key_operations == nil or input.target_key_operations == "" then
    -- Use default key operations based on key type
    key_operations = { 'ENCRYPT', 'DECRYPT', 'SIGN', 'VERIFY', 'WRAP', 'UNWRAP' }
    if input.target_key_type == 'AES' then
        key_operations = { 'ENCRYPT', 'DECRYPT', 'WRAP', 'UNWRAP' }
    end
  else
    key_operations = input.target_key_operations
  end

  local algorithm = 'RSA_AES_WRAP_SHA256'
  if input.target_key_type == 'AES' then
    algorithm = 'OAEP_MGF1_SHA256'
  end

  -- Uwrap API Reference : https://api-kms-v2-preprod.datacustodian.cloud.sap/kms/v2/ui/#/Cryptography/unwrap
  local request_body
  -- Import operation - Call unwrap API with schema for "UnwrapNewKey"
  if input.operation == 'import' then
    if is_aws_key_store == true then 
      request_body = json.encode({ 
        wrappedKey = wrapped_key_value,
        targetKeyId = target_key_id
      })
    else 
      request_body = json.encode({ 
        algorithm = algorithm, 
        keyId = input.kek_key_id,
        version = 0,
        wrappedKey = wrapped_key_value,
        target = {
            name = input.target_key_name,
            description = input.target_key_description,
            groupId = input.datacustodian_group_id,
            type = input.target_key_type,
            exportable = input.is_exportable,
            enabled = true,
            operations = key_operations,
            role = input.datacustodian_role,
        }
    })
    end
  else
    -- Rotate operation - Call unwrap API with schema for "UnwrapKeyVersion"
    if is_aws_key_store == true then 
      request_body = json.encode({ 
        wrappedKey = wrapped_key_value,
        targetKeyId = input.datacustodian_key_id
      })
    else 
      request_body = json.encode({ 
        algorithm = algorithm, 
        keyId = input.kek_key_id,
        version = input.kek_key_version,
        targetKeyId = input.datacustodian_key_id,
        wrappedKey = wrapped_key_value
      })
    end
  end

  local url = base_url .. '/kms/v2/crypto/unwrap'
  local response, err = request { method = "POST", url = url, headers = headers, body=request_body }
  if err ~= nil then
    return {result = nil, error = err}
  end
  if response.status ~= 200 then
    decoded_body = json.decode(response.body)
    response.body = decoded_body
    return {result = nil, error = response}
  end
  if is_aws_key_store == true then
    return {result = json.decode(response.body),kek_key_id = kek_key_id, error = nil}
  else 
    return {result = json.decode(response.body), error = nil}
  end
end

function is_valid(operation)
  local opr = {'configure', 'import', 'rotate'}
  for i=1,#opr do
    if opr[i] == operation then
      return true
    end
  end
  return false
end

function is_valid_target_key_type(key_type)
  local key_types = {'AES', 'RSA'}
  for i=1,#key_types do
    if key_types[i] == key_type then
      return true
    end
  end
  return false
end

function is_valid_dsm_key(name)
  local response, err = Sobject {name = name}
  if err ~=nil or response == nil then
    return false
  end
  return true
end

function check_aws_key_store(base_url, headers, datacustodian_group_id) 
  local url = base_url .. '/kms/v2/groups?$filter=id eq ' .. datacustodian_group_id .. '&$expand=keystore'
  local response, err = request { method = "GET", url = url, headers = headers, body=request_body }
  if err ~= nil then
    return {result = nil, error = err}
  end
  if response.status ~= 200 then
    decoded_body = json.decode(response.body)
    response.body = decoded_body
    return {result = nil, error = response, message = 'Failed to obtain provider information of the group'}
  end
  
  local json_resp = json.decode(response.body)
  if json_resp.value[1] == nil then
    return {result = nil, error = json_resp,  message = "Provider information not received as a part of response, please check the given group id and authentication credentials"}
  end 
  local provider = json_resp.value[1].keystore.provider

  if provider == 'AWS' then 
    return {result = true, error = nil}
  else 
    return {result = false, error = nil}
  end
end

function check(input)
  if input.operation == 'configure' then
    if input.api_key == nil then
      return nil, 'input parameter api_key required'
    end
    if input.secret == nil then
      return nil, 'input parameter secret required'
    end
    if input.base_url == nil then
      return nil, 'input parameter base_url required'
    end
    if not string.match(input.base_url,'^https?://[^/]+$') then
      return nil, 'input parameter base_url must not include a path or must be a valid URL.'
    end
  elseif input.operation == 'import' or input.operation == 'rotate' then
    if input.secret_id == nil or input.secret_id == "" then
      return nil, 'input parameter secret_id required'
    end
    if input.target_key_name == nil or input.target_key_name == "" then
      return nil, 'input parameter target_key_name required'
    end
  end
  if input.operation == 'import' then
    if input.datacustodian_group_id == nil or input.datacustodian_group_id == "" then
      return nil, 'input parameter datacustodian_group_id required'
    end
    if input.target_key_type == nil or input.target_key_type == "" then
      return nil, 'input parameter target_key_type required'
    else
      if not is_valid_target_key_type(input.target_key_type) then
        return {result = nil, error = "Target key type is not valid. Target key type should be one of `RSA`, `AES`"}
      end
    end
    if input.target_key_description == nil or input.target_key_description == "" then
      return nil, 'input parameter target_key_description required'
    end
    if input.target_key_size == nil or input.target_key_size == "" then
      return nil, 'input parameter target_key_size required'
    end
  elseif input.operation == 'rotate' then
    if input.datacustodian_key_id == nil or input.datacustodian_key_id == "" then
      return nil, 'input parameter datacustodian_key_id required'
    end
    if input.datacustodian_group_id == nil or input.datacustodian_group_id == "" then
      return nil, 'input parameter datacustodian_group_id required'
    end
  end
end

function is_valid_input_for_aws_group(input, is_aws_key_store) 
  if input.operation == 'import' or input.operation == 'rotate' then
    if is_aws_key_store == false then 
      if input.kek_key_id == nil or input.kek_key_id == "" then
        return nil, 'input parameter kek_key_id required for this group'
      end
      if input.kek_key_version == nil or input.kek_key_version == "" then
        return nil, 'input parameter kek_key_version required for this group'
      end
    end
  end
  if input.operation == 'import' then  
    if is_aws_key_store == true then 
      if input.kek_key_size == nil or input.kek_key_size == "" then
        return nil, 'input parameter kek_key_size required for AWS group'
      end
      if input.target_key_operations == nil or input.target_key_operations == "" then
        return nil, 'input parameter target_key_operations required for AWS group'
      end
    else 
      if input.is_exportable == nil or input.is_exportable == "" then
        return nil, 'input parameter is_exportable required for this group'
      end
    end
  end
  return true
end

function run(input)
  if not is_valid(input.operation) then
    return {result = nil, error = "Operation is not valid. Operation value should be one of `configure`, `import`, `rotate`."}
  end

  if input.operation == 'configure' then
    return configure_credentials(input.api_key, input.secret, input.base_url)
  else
    local resp, err, message = login(input.secret_id)
    if resp.result == nil then
      return {result = resp, error = err, message = message}
    end
    local base_url = Sobject { id = input.secret_id }.custom_metadata['base_url']
    local authorization_header = 'Bearer ' ..resp.result
    headers = {['Content-Type'] = 'application/json', ['Authorization'] = authorization_header}

    resp, err, message = check_aws_key_store(base_url, headers, input.datacustodian_group_id)
    if resp.result == nil then
      return {result = resp, error = err, message = message}
    end
    local is_aws_key_store = resp.result
    local json_input_validation,err = is_valid_input_for_aws_group(input,is_aws_key_store)
    if json_input_validation == nil then 
      return err
    end

    if input.operation == 'import' or input.operation == 'rotate' then
      if input.operation == 'create' and is_valid_dsm_key(input.target_key_name) then
        return "Error in creating target key or the key already exists in DSM."
      end
      if input.operation == 'rotate' and not is_valid_dsm_key(input.target_key_name) then
        return "The key does not exist in DSM. Can not rotate. For rotate operation the key specified by target_key_name must already exist in DSM and the key specified by datacustodian_key_id must already exist in Data custodian"
      end

      local is_transient = true
      local target_key

      if input.operation == 'import' then
        -- create target key - we will import this target key in data custodian
        target_key = create_target_key(headers, base_url, is_aws_key_store, input)
      else
        -- Rotate target key in DSM - we will import the new rotated key in data custodian
        target_key = rotate_target_key(input.target_key_name)
        input.target_key_type = target_key.obj_type
      end
      if target_key.result == nil then
        return target_key
      end

      if input.operation == 'rotate' then
        input.target_key_type = target_key.result.obj_type
      end

      -- Create the KEK and import into DSM
      local config_kek_key_resp = config_kek_key(headers, base_url, target_key.target_key_id, is_aws_key_store, input, is_transient)
      if config_kek_key_resp.result == nil then
        return config_kek_key_resp
      end

      local wrapped_wrapping_key = nil
      local wrapped_target_key = nil
      if input.target_key_type == 'RSA' then
        -- create ephemeral wrapping key used to wrap target key
        local wrapping_key = create_wrapping_key(is_transient)
        if wrapping_key.result == nil then
            return wrapping_key
        end
        -- wrap ephemeral wrapping key with kek key
        wrapped_wrapping_key = wrap_rsa(config_kek_key_resp.result, wrapping_key.result)
        if wrapped_wrapping_key.result == nil then
            return wrapped_wrapping_key
        end
        -- Wrap target key with ephemeral key
        wrapped_target_key = wrap_aes(wrapping_key.result, target_key.result)
        if wrapped_target_key.result == nil then
            return wrapped_target_key
        end
      elseif input.target_key_type == 'AES' then
        -- wrap target key with kek key
        wrapped_target_key = wrap_rsa(config_kek_key_resp.result, target_key.result)
        if wrapped_target_key.result == nil then
            return wrapped_target_key
        end
      end

      local wrapped_byok_value = get_wrapped_byok_value(input.target_key_type, wrapped_wrapping_key, wrapped_target_key)
      local response = perform_byok(headers, base_url, wrapped_byok_value, target_key.target_key_id, config_kek_key_resp.kek_key_id, is_aws_key_store, input)
      -- Delete if non transient KEK and Wrapping keys were created
      if not is_transient then
        config_kek_key_resp.result:delete()
        wrapping_key.result:delete()
      end
      return response
    else
      return {result = '', error = "Operation is not valid. Operation value should be one of `configure`, `import`, or `rotate`."}
    end
  end
end
