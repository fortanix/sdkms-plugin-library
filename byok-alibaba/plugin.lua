--[[
-- Name: Alibaba Cloud BYOK with Fortanix DSM
-- Version: 1.0
-- Date: September 18, 2025

--configure
{
  "operation": "configure",
  "access_key_id": "LTAI.....jkgd",
  "access_key_secret": "6DG.....l4aTR",
  "region": "ap-southeast-6"
}

--create
{
  "operation": "create",
  "secret_id": "f23e9a85-xxxx-xxxx-xxxx-1bb2cc38a339",
  "key_name": "cmk-aes-1",
  "key_spec": "Aliyun_AES_256",
  "description": "Test BYOK key from DSM",
  "dkms_instance_id": "kst-php68c9f961t5t2de4gs3"
}

--list
{
  "operation": "list",
  "secret_id": "f23e9a85-xxxx-xxxx-xxxx-1bb2cc38a339"
}

--disable
{
  "operation": "disable",
  "secret_id": "f23e9a85-xxxx-xxxx-xxxx-1bb2cc38a339",
  "key_name": "cmk-aes-1"
}

--enable
{
  "operation": "enable",
  "secret_id": "f23e9a85-xxxx-xxxx-xxxx-1bb2cc38a339",
  "key_name": "cmk-aes-1"
}

--delete_key_material (immediately removes key material)
{
  "operation": "delete_key_material",
  "secret_id": "f23e9a85-xxxx-xxxx-xxxx-1bb2cc38a339",
  "key_name": "cmk-aes-1"
}

--delete
{
  "operation": "delete",
  "secret_id": "f23e9a85-xxxx-xxxx-xxxx-1bb2cc38a339",
  "key_name": "cmk-aes-1",
  "retention_period": 366
}

--import_to_existing (import new key material to existing CMK shell)
{
  "operation": "import_to_existing",
  "secret_id": "f23e9a85-xxxx-xxxx-xxxx-1bb2cc38a339",
  "key_name": "re-imported-key",
  "alibaba_key_id": "key-php68cb54ddsavipurcor",
  "key_spec": "Aliyun_AES_256"
}

--]]

local content_type = 'application/x-www-form-urlencoded'
local api_version = '2016-01-20'
local session_token = ''
local region = ''

-- Helper function for URL encoding (RFC 3986)
function url_encode(str)
    if str then
        str = string.gsub(str, "([^%w%-%.%_%~])",
            function(c) return string.format("%%%02X", string.byte(c)) end)
    end
    return str
end

-- Helper function to sort query parameters

local content_type = 'application/x-www-form-urlencoded'
local api_version = '2016-01-20'
local session_token = ''
local region = ''

-- Helper function for URL encoding (RFC 3986)
function url_encode(str)
    if str then
        str = string.gsub(str, "([^%w%-%.%_%~])",
            function(c) return string.format("%%%02X", string.byte(c)) end)
    end
    return str
end

-- Helper function to sort query parameters

local content_type = 'application/x-www-form-urlencoded'
local api_version = '2016-01-20'
local session_token = ''
local region = ''

-- Helper function for URL encoding (RFC 3986)
function url_encode(str)
    if str then
        str = string.gsub(str, "([^%w%-%.%_%~])",
            function(c) return string.format("%%%02X", string.byte(c)) end)
    end
    return str
end

-- Helper function to sort query parameters

local content_type = 'application/x-www-form-urlencoded'
local api_version = '2016-01-20'
local session_token = ''
local region = ''

-- Helper function for URL encoding (RFC 3986)
function url_encode(str)
    if str then
        str = string.gsub(str, "([^%w%-%.%_%~])",
            function(c) return string.format("%%%02X", string.byte(c)) end)
    end
    return str
end

-- Helper function to sort query parameters

local content_type = 'application/x-www-form-urlencoded'
local api_version = '2016-01-20'
local session_token = ''
local region = ''

-- Helper function for URL encoding (RFC 3986)
function url_encode(str)
    if str then
        str = string.gsub(str, "([^%w%-%.%_%~])",
            function(c) return string.format("%%%02X", string.byte(c)) end)
    end
    return str
end

-- Helper function to sort query parameters

local content_type = 'application/x-www-form-urlencoded'
local api_version = '2016-01-20'
local session_token = ''
local region = ''

-- Helper function for URL encoding (RFC 3986)
function url_encode(str)
    if str then
        str = string.gsub(str, "([^%w%-%.%_%~])",
            function(c) return string.format("%%%02X", string.byte(c)) end)
    end
    return str
end

-- Helper function to sort query parameters

local content_type = 'application/x-www-form-urlencoded'
local api_version = '2016-01-20'
local session_token = ''
local region = ''

-- Helper function for URL encoding (RFC 3986)
function url_encode(str)
    if str then
        str = string.gsub(str, "([^%w%-%.%_%~])",
            function(c) return string.format("%%%02X", string.byte(c)) end)
    end
    return str
end

-- Helper function to sort query parameters

local content_type = 'application/x-www-form-urlencoded'
local api_version = '2016-01-20'
local session_token = ''
local region = ''

-- Helper function for URL encoding (RFC 3986)
function url_encode(str)
    if str then
        str = string.gsub(str, "([^%w%-%.%_%~])",
            function(c) return string.format("%%%02X", string.byte(c)) end)
    end
    return str
end

-- Helper function to sort query parameters

local content_type = 'application/x-www-form-urlencoded'
local api_version = '2016-01-20'
local session_token = ''
local region = ''

-- Helper function for URL encoding (RFC 3986)
function url_encode(str)
    if str then
        str = string.gsub(str, "([^%w%-%.%_%~])",
            function(c) return string.format("%%%02X", string.byte(c)) end)
    end
    return str
end

-- Helper function to sort query parameters

local content_type = 'application/x-www-form-urlencoded'
local api_version = '2016-01-20'
local session_token = ''
local region = ''

-- Helper function for URL encoding (RFC 3986)
function url_encode(str)
    if str then
        str = string.gsub(str, "([^%w%-%.%_%~])",
            function(c) return string.format("%%%02X", string.byte(c)) end)
    end
    return str
end

-- Helper function to sort query parameters

local content_type = 'application/x-www-form-urlencoded'
local api_version = '2016-01-20'
local session_token = ''
local region = ''

-- Helper function for URL encoding (RFC 3986)
function url_encode(str)
    if str then
        str = string.gsub(str, "([^%w%-%.%_%~])",
            function(c) return string.format("%%%02X", string.byte(c)) end)
    end
    return str
end

-- Helper function to sort query parameters

local content_type = 'application/x-www-form-urlencoded'
local api_version = '2016-01-20'
local session_token = ''
local region = ''

-- Helper function for URL encoding (RFC 3986)
function url_encode(str)
    if str then
        str = string.gsub(str, "([^%w%-%.%_%~])",
            function(c) return string.format("%%%02X", string.byte(c)) end)
    end
    return str
end

-- Helper function to sort query parameters

local content_type = 'application/x-www-form-urlencoded'
local api_version = '2016-01-20'
local session_token = ''
local region = ''

-- Helper function for URL encoding (RFC 3986)
function url_encode(str)
    if str then
        str = string.gsub(str, "([^%w%-%.%_%~])",
            function(c) return string.format("%%%02X", string.byte(c)) end)
    end
    return str
end

-- Helper function to sort query parameters

local content_type = 'application/x-www-form-urlencoded'
local api_version = '2016-01-20'
local session_token = ''
local region = ''

-- Helper function for URL encoding (RFC 3986)
function url_encode(str)
    if str then
        str = string.gsub(str, "([^%w%-%.%_%~])",
            function(c) return string.format("%%%02X", string.byte(c)) end)
    end
    return str
end

-- Helper function to sort query parameters

local content_type = 'application/x-www-form-urlencoded'
local api_version = '2016-01-20'
local session_token = ''
local region = ''

-- Helper function for URL encoding (RFC 3986)
function url_encode(str)
    if str then
        str = string.gsub(str, "([^%w%-%.%_%~])",
            function(c) return string.format("%%%02X", string.byte(c)) end)
    end
    return str
end

-- Helper function to sort query parameters

local content_type = 'application/x-www-form-urlencoded'
local api_version = '2016-01-20'
local session_token = ''
local region = ''

-- Helper function for URL encoding (RFC 3986)
function url_encode(str)
    if str then
        str = string.gsub(str, "([^%w%-%.%_%~])",
            function(c) return string.format("%%%02X", string.byte(c)) end)
    end
    return str
end

-- Helper function to sort query parameters
function sort_query_params(params)
    local keys = {}
    for k in pairs(params) do
        table.insert(keys, k)
    end
    table.sort(keys)
    return keys
end

-- Generate canonical query string
function canonical_query_string(params)
    local sorted_keys = sort_query_params(params)
    local query_parts = {}
    for _, key in ipairs(sorted_keys) do
        table.insert(query_parts, url_encode(key) .. "=" .. url_encode(tostring(params[key])))
    end
    return table.concat(query_parts, "&")
end

-- HMAC-SHA1 signing function
function sign_hmac_sha1(key, msg)
    assert(type(key) == 'string' and type(msg) == 'string')
    local hmac_key = assert(Sobject.import { obj_type = 'HMAC', value = Blob.from_bytes(key), transient = true })
    return assert(hmac_key:mac { alg = 'SHA1', data = Blob.from_bytes(msg) }).digest
end

-- Generate Alibaba Cloud API signature
function generate_signature(access_key_secret, string_to_sign)
    local signature_key = access_key_secret .. "&"
    return sign_hmac_sha1(signature_key, string_to_sign):base64()
end

-- Create string to sign for Alibaba Cloud API
function create_string_to_sign(method, params)
    local sorted_keys = sort_query_params(params)
    local query_parts = {}
    for _, key in ipairs(sorted_keys) do
        table.insert(query_parts, url_encode(key) .. "=" .. url_encode(tostring(params[key])))
    end
    local canonical_query = table.concat(query_parts, "&")
    return method .. "&" .. url_encode("/") .. "&" .. url_encode(canonical_query)
end

-- Get current timestamp in ISO format
function get_timestamp()
    -- Get current timestamp using Time.now_insecure()
    local timestamp = Time.now_insecure():to_iso8601()
    
    -- Convert from DSM format (YYYYMMDDTHHMMSSZ) to Alibaba format (YYYY-MM-DDTHH:MM:SSZ)
    local year = timestamp:sub(1, 4)
    local month = timestamp:sub(5, 6)
    local day = timestamp:sub(7, 8)
    local hour = timestamp:sub(10, 11)
    local minute = timestamp:sub(12, 13)
    local second = timestamp:sub(14, 15)
    return year .. "-" .. month .. "-" .. day .. "T" .. hour .. ":" .. minute .. ":" .. second .. "Z"
end

-- Generate random nonce
function generate_nonce()
    return Blob.random { bits = 128 }:hex()
end

-- Configure Alibaba Cloud credentials
function configure_credentials(access_key_id, access_key_secret, region_id)
    local name = Blob.random { bits = 64 }:hex()
    local secret = assert(Sobject.import{ 
        name = name, 
        obj_type = "SECRET", 
        value = Blob.from_bytes(access_key_secret),
        custom_metadata = {
            ["AccessKeyId"] = access_key_id,
            ["Region"] = region_id
        }
    })
    return secret
end

-- Get session credentials
function get_session(secret_id)
    local sobject, err = Sobject { id = secret_id }
    if sobject == nil or err ~= nil then
        return nil, "Alibaba Cloud credentials are not configured or incorrect. Please run configure operation."
    end
    
    if sobject.custom_metadata == nil or 
       sobject.custom_metadata["AccessKeyId"] == nil or 
       sobject.custom_metadata["Region"] == nil then
        return nil, "Alibaba Cloud credentials are not configured or incorrect. Please run configure operation."
    end
    
    local access_key_id = sobject.custom_metadata["AccessKeyId"]
    local access_key_secret = sobject:export().value:bytes()
    local region_id = sobject.custom_metadata["Region"]
    
    return {
        access_key_id = access_key_id,
        access_key_secret = access_key_secret,
        region = region_id
    }, nil
end

-- Make Alibaba Cloud KMS API request
function alibaba_request(secret_id, action, params)
    local session, err = get_session(secret_id)
    if session == nil then
        return nil, err
    end
    
    -- Base parameters for all requests
    local request_params = {
        AccessKeyId = session.access_key_id,
        Action = action,
        Format = "JSON",
        RegionId = session.region,
        SignatureMethod = "HMAC-SHA1",
        SignatureNonce = generate_nonce(),
        SignatureVersion = "1.0",
        Timestamp = get_timestamp(),
        Version = api_version
    }
    
    -- Add action-specific parameters
    if params then
        for k, v in pairs(params) do
            request_params[k] = v
        end
    end
    
    -- Generate signature
    local string_to_sign = create_string_to_sign("POST", request_params)
    local signature = generate_signature(session.access_key_secret, string_to_sign)
    request_params.Signature = signature
    
    -- Build request body
    local query_string = canonical_query_string(request_params)
    
    -- Build URL and headers
    local endpoint = "https://kms." .. session.region .. ".aliyuncs.com/"
    local headers = { ['Content-Type'] = content_type }
    
    local response, err = request { method = "POST", url = endpoint, headers = headers, body = query_string }
    if response == nil or err ~= nil then
        return nil, err
    end
    
    if response.status >= 400 then
        if response.body ~= nil then
            local err_decoded = json.decode(response.body)
            return nil, err_decoded
        end
        return nil, response
    end
    
    return json.decode(response.body), nil
end

-- Create a new CMK with external origin for BYOK
function alibaba_create_key(secret_id, key_name, key_spec, description, dkms_instance_id)
    local params = {
        Origin = "EXTERNAL",
        KeySpec = key_spec or "Aliyun_AES_256",
        KeyUsage = "ENCRYPT/DECRYPT"
    }
    
    -- Add DKMSInstanceId if provided (for Software KMS)
    if dkms_instance_id then
        params.DKMSInstanceId = dkms_instance_id
    end
    
    if description then
        params.Description = description
    end
    
    local response, err = alibaba_request(secret_id, "CreateKey", params)
    if response == nil then
        return nil, err
    end
    
    return response, nil
end

-- Get parameters for importing key material
function alibaba_get_import_params(secret_id, key_id)
    local params = {
        KeyId = key_id,
        WrappingAlgorithm = "RSAES_OAEP_SHA_256",
        WrappingKeySpec = "RSA_2048"
    }
    
    local response, err = alibaba_request(secret_id, "GetParametersForImport", params)
    return response, err
end

-- Import key material to the CMK
function alibaba_import_key_material(secret_id, key_id, encrypted_key_material, import_token, expire_unix)
    local params = {
        KeyId = key_id,
        EncryptedKeyMaterial = encrypted_key_material,
        ImportToken = import_token
    }
    if expire_unix ~= nil then
        params.KeyMaterialExpireUnix = expire_unix
    end
    
    local response, err = alibaba_request(secret_id, "ImportKeyMaterial", params)
    return response, err
end

-- List all CMKs
function alibaba_list_keys(secret_id, page_number, page_size)
    local params = {
        PageNumber = page_number or 1,
        PageSize = page_size or 10
    }
    
    local response, err = alibaba_request(secret_id, "ListKeys", params)
    return response, err
end

-- Enable a CMK
function alibaba_enable_key(secret_id, key_id)
    local params = { KeyId = key_id }
    local response, err = alibaba_request(secret_id, "EnableKey", params)
    return response, err
end

-- Disable a CMK
function alibaba_disable_key(secret_id, key_id)
    local params = { KeyId = key_id }
    local response, err = alibaba_request(secret_id, "DisableKey", params)
    return response, err
end

-- Schedule key deletion
function alibaba_schedule_key_deletion(secret_id, key_id, retention_period)
    local params = {
        KeyId = key_id,
        PendingWindowInDays = retention_period or 366
    }
    local response, err = alibaba_request(secret_id, "ScheduleKeyDeletion", params)
    return response, err
end

-- Cancel key deletion
function alibaba_cancel_key_deletion(secret_id, key_id)
    local params = { KeyId = key_id }
    local response, err = alibaba_request(secret_id, "CancelKeyDeletion", params)
    return response, err
end

-- Delete key material (immediately removes imported key material)
function alibaba_delete_key_material(secret_id, key_id)
    local params = { KeyId = key_id }
    local response, err = alibaba_request(secret_id, "DeleteKeyMaterial", params)
    return response, err
end

-- Get key information
function alibaba_describe_key(secret_id, key_id)
    local params = { KeyId = key_id }
    local response, err = alibaba_request(secret_id, "DescribeKey", params)
    return response, err
end

-- Wrap key material for import
function wrap_key_for_import(master_key, import_params)
    -- Import Alibaba Cloud public key
    local public_key = assert(Sobject.import { 
        obj_type = 'RSA', 
        transient = true, 
        value = Blob.from_base64(import_params.PublicKey)
    })
    
    -- Verify key is AES-256 (32 bytes / 256 bits)
    assert(master_key.key_size == 256, "Key material must be AES-256 (256 bits), got: " .. master_key.key_size .. " bits")
    
    -- Try wrap operation with the master key object directly
    local wrap_response = assert(public_key:wrap { 
        subject = master_key, 
        mode = 'OAEP_MGF1_SHA256'
    })
    
    return wrap_response.wrapped_key:base64()
end

-- Generate key material based on key specification
function generate_key_material(key_spec, key_name)
    local key_size
    local obj_type
    
    if key_spec == "Aliyun_AES_256" then
        key_size = 256
        obj_type = "AES"
        key_ops = {'ENCRYPT', 'DECRYPT', 'APPMANAGEABLE', 'EXPORT'}
    else
        return nil, "Unsupported key specification: " .. key_spec
    end
    
    local master_key, err = Sobject.create { 
        name = key_name,
        obj_type = obj_type, 
        key_size = key_size,
        key_ops = key_ops
    }
    
    if master_key == nil then
        return nil, err
    end
    
    return master_key, nil
end

-- Main operations handler
function check(input)
    if input.operation == nil then
        return nil, "Operation parameter is required"
    end
    
    -- Check required parameters for each operation
    if input.operation == "configure" then
        if input.access_key_id == nil then
            return nil, "access_key_id is required for configure operation"
        end
        if input.access_key_secret == nil then
            return nil, "access_key_secret is required for configure operation"
        end
        if input.region == nil then
            return nil, "region is required for configure operation"
        end
        
    elseif input.operation == "create" then
        if input.secret_id == nil then
            return nil, "secret_id is required for create operation"
        end
        if input.key_name == nil then
            return nil, "key_name is required for create operation"
        end
        
    elseif input.operation == "import_to_existing" then
        if input.secret_id == nil then
            return nil, "secret_id is required for import_to_existing operation"
        end
        if input.key_name == nil then
            return nil, "key_name is required for import_to_existing operation"
        end
        if input.alibaba_key_id == nil then
            return nil, "alibaba_key_id is required for import_to_existing operation"
        end
        
    elseif input.operation == "list" then
        if input.secret_id == nil then
            return nil, "secret_id is required for list operation"
        end
        
    elseif input.operation == "enable" or input.operation == "disable" then
        if input.secret_id == nil then
            return nil, "secret_id is required for " .. input.operation .. " operation"
        end
        if input.key_name == nil then
            return nil, "key_name is required for " .. input.operation .. " operation"
        end
        
    elseif input.operation == "delete" then
        if input.secret_id == nil then
            return nil, "secret_id is required for delete operation"
        end
        if input.key_name == nil then
            return nil, "key_name is required for delete operation"
        end
        if input.retention_period ~= nil then
            if type(input.retention_period) ~= "number" or input.retention_period < 7 or input.retention_period > 366 then
                return nil, "retention_period must be a number between 7 and 366 days"
            end
        end
        
    elseif input.operation == "delete_key_material" then
        if input.secret_id == nil then
            return nil, "secret_id is required for delete_key_material operation"
        end
        if input.key_name == nil then
            return nil, "key_name is required for delete_key_material operation"
        end
             
    else
        return nil, "Unsupported operation: " .. input.operation
    end    
    return nil
end

function run(input)
    if input.operation == "configure" then
        local secret = configure_credentials(input.access_key_id, input.access_key_secret, input.region)
        return {secret_id = secret.kid}
        
    elseif input.operation == "create" then
        -- Create key
        
        -- Generate key material in DSM
        local master_key, err = generate_key_material(input.key_spec or "Aliyun_AES_256", input.key_name)
        if master_key == nil then
            return { result = nil, error = err, message = "Failed to generate key material in DSM" }
        end
        
        -- Create CMK in Alibaba Cloud
        local alibaba_key, err = alibaba_create_key(input.secret_id, input.key_name, input.key_spec, input.description, input.dkms_instance_id)
        if alibaba_key == nil then
            master_key:delete()
            return { result = alibaba_key, error = err, message = "Failed to create CMK in Alibaba Cloud" }
        end
        
        local key_id = alibaba_key.KeyMetadata.KeyId
        
        -- Get import parameters
        local import_params, err = alibaba_get_import_params(input.secret_id, key_id)
        if import_params == nil then
            master_key:delete()
            return { result = import_params, error = err, message = "Failed to get import parameters" }
        end
        
        -- Wrap key material
        local wrapped_key = wrap_key_for_import(master_key, import_params)
        
        -- Import key material
        local import_result, err = alibaba_import_key_material(input.secret_id, key_id, wrapped_key, import_params.ImportToken, input.expire_unix)
        if import_result == nil then
            master_key:delete()
            return { result = import_result, error = err, message = "Failed to import key material" }
        end
        
        -- Update master key metadata
        master_key:update {
            custom_metadata = {
                ALIBABA_KEY_ID = key_id,
                ALIBABA_CREATED = alibaba_key.KeyMetadata.CreationDate
            }
        }
        
        return Sobject { name = input.key_name }
        
    elseif input.operation == "import_to_existing" then
        -- Import new key material to existing CMK shell 
        
        -- Generate key material in DSM
        local master_key, err = generate_key_material(input.key_spec or "Aliyun_AES_256", input.key_name)
        if master_key == nil then
            return { result = nil, error = err, message = "Failed to generate key material in DSM" }
        end
        
        -- Get import parameters for existing CMK
        local import_params, err = alibaba_get_import_params(input.secret_id, input.alibaba_key_id)
        if import_params == nil then
            -- master_key:delete()
            return { result = import_params, error = err, message = "Failed to get import parameters" }
        end
        
        -- Wrap key material
        local wrapped_key = wrap_key_for_import(master_key, import_params)
        
        -- Import key material to existing CMK
        local import_result, err = alibaba_import_key_material(input.secret_id, input.alibaba_key_id, wrapped_key, import_params.ImportToken, input.expire_unix)
        if import_result == nil then
            -- master_key:delete()
            return { result = import_result, error = err, message = "Failed to import key material" }
        end
        
        -- Update master key metadata to link with existing Alibaba CMK
        master_key:update {
            custom_metadata = {
                ALIBABA_KEY_ID = input.alibaba_key_id,
                ALIBABA_CREATED = get_timestamp()
            }
        }
        
        return Sobject { name = input.key_name }
        
    elseif input.operation == "list" then
        local keys, err = alibaba_list_keys(input.secret_id, input.page_number, input.page_size)
        if keys == nil and err ~= nil then
            return { result = nil, error = err, message = "Failed to list keys" }
        end
        return keys
        
    elseif input.operation == "enable" then
        local key = assert(Sobject { name = input.key_name })
        if key.custom_metadata == nil or key.custom_metadata.ALIBABA_KEY_ID == nil then
            return "The key " .. input.key_name .. " is not a valid Alibaba Cloud BYOK key"
        end
        
        local resp, err = alibaba_enable_key(input.secret_id, key.custom_metadata.ALIBABA_KEY_ID)
        if resp == nil then 
            return { result = nil, error = err }
        end
        
        -- Update DSM key state
        key:update { enabled = true, custom_metadata = key.custom_metadata }
        return resp
        
    elseif input.operation == "disable" then
        local key = assert(Sobject { name = input.key_name })
        if key.custom_metadata == nil or key.custom_metadata.ALIBABA_KEY_ID == nil then
            return "The key " .. input.key_name .. " is not a valid Alibaba Cloud BYOK key"
        end
        
        local resp, err = alibaba_disable_key(input.secret_id, key.custom_metadata.ALIBABA_KEY_ID)
        if resp == nil then 
            return { result = nil, error = err }
        end
        
        -- Update DSM key state
        key:update { enabled = false, custom_metadata = key.custom_metadata }
        return resp
        
    elseif input.operation == "delete" then
        local key = assert(Sobject { name = input.key_name })
        if key.custom_metadata == nil or key.custom_metadata.ALIBABA_KEY_ID == nil then
            return "The key " .. input.key_name .. " is not a valid Alibaba Cloud BYOK key"
        end
        
        local resp, err = alibaba_schedule_key_deletion(input.secret_id, key.custom_metadata.ALIBABA_KEY_ID, input.retention_period)
        if resp == nil then 
            return { result = nil, error = err }
        end
        return resp
        
    elseif input.operation == "delete_key_material" then
        local key = assert(Sobject { name = input.key_name })
        if key.custom_metadata == nil or key.custom_metadata.ALIBABA_KEY_ID == nil then
            return "The key " .. input.key_name .. " is not a valid Alibaba Cloud BYOK key"
        end
        
        local resp, err = alibaba_delete_key_material(input.secret_id, key.custom_metadata.ALIBABA_KEY_ID)
        if resp == nil then 
            return { result = nil, error = err }
        end
        return resp
        
    else
        return { result = nil, error = "Unsupported operation: " .. (input.operation or "none") }
    end
end