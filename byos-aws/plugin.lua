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
  "access_key": "AK...ZCX",
  "region": "us-west-1"
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
  "secret_id": "0aa4a0af-514c-4873-b13b-"
}


3. List: Description: Lists the properties and current state of a secret managed by the local secret management system. This can include metadata such as creation date, last modified date, and version information.

Operation: list
Parameters:

secret_id: The identifier for the secret whose details are to be listed.

Sample JSON:

{
  "operation": "list",
  "secret_id": "0aa4a0af-514c-4873-b13b-"
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
  "secret_id": "0aa4a0af-514c-4873-b13b-"
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
  "secret_id": "90023544-c34f-4545-85a2-"
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
  "secret_id": "90023544-c34f-4545-85a2-"
}


10. Export: Exports a secret from Fortanix DSM to AWS Secret Manager.

Operation: Export

Parameters:

dsm_secret_name": the name of secret in dsm 
aws_secret_name": the of secret which has to be in AWS secret manager
secret_id": 


name: The name of the secret to be restored.
secret_id: The identifier for the secret to be restored.

Sample JSON:

{
  "operation": "export",
  "dsm_secret_name": "export21",
  "aws_secret_name": "export21",
   "secret_id": "4ac0c969-5a82-4e5c-938a-"
}
 
--]]

local session_ttl = 900 -- 15 mins
local clean_after_expire = 7 -- deactivate after days since token expiry

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

-- Function to simulate error extraction 
function extractError(err)
    return tostring(err)
end

-- Utility function to parse and format timestamps
function gmtime(t)
    local floor=math.floor

    local DSEC=24*60*60 -- secs in a day
    local YSEC=365*DSEC -- secs in a year
    local LSEC=YSEC+DSEC    -- secs in a leap year
    local FSEC=4*YSEC+DSEC  -- secs in a 4-year interval
    local BASE_DOW=4    -- 1970-01-01 was a Thursday
    local BASE_YEAR=1970    -- 1970 is the base year

    local _days={
        -1, 30, 58, 89, 119, 150, 180, 211, 242, 272, 303, 333, 364
    }
    local _lpdays={}
    for i=1,2  do _lpdays[i]=_days[i]   end
    for i=3,13 do _lpdays[i]=_days[i]+1 end
  
    local y,j,m,d,w,h,n,s
    local mdays=_days
    s=t
    y=floor(s/FSEC)
    s=s-y*FSEC
    y=y*4+BASE_YEAR        
    if s>=YSEC then
        y=y+1          
        s=s-YSEC
        if s>=YSEC then
            y=y+1       
            s=s-YSEC
            if s>=LSEC then
                y=y+1   
                s=s-LSEC
            else        -- leap year
                mdays=_lpdays
            end
        end
    end
    j=floor(s/DSEC)
    s=s-j*DSEC
    local m=1
    while mdays[m]<j do m=m+1 end
    m=m-1
    local d=j-mdays[m]
    -- Calculate day of week. Sunday is 0
    w=(floor(t/DSEC)+BASE_DOW)%7
    -- Calculate the time of day from the remaining seconds
    h=floor(s/3600)
    s=s-h*3600
    n=floor(s/60)
    s=s-n*60
    return d.."-"..m.."-"..y.." "..h..":"..n..":"..math.floor(s)
end


function aws_request(secret_id, amzTarget, request_body, method)
    local sobject, err = assert(Sobject { id = secret_id })
    if not sobject or not sobject.custom_metadata then
        return nil, "Failed to retrieve secret or metadata: " .. (err or "Metadata is missing")
    end

    local access_key = sobject.custom_metadata['AccessKey']
    local region = sobject.custom_metadata['Region']
    if not access_key or not region then
        return nil, "AWS credentials or region are not configured properly."
    end

    local service = 'secretsmanager'
    local host = service .. '.' .. region .. '.amazonaws.com'
    local endpoint = 'https://' .. host

  local sobject, err = assert(Sobject { id = secret_id })
  if sobject.custom_metadata["AccessKey"] == nil then
     err = "AWS credential is not configured or incorrect. Please run configure operation."
    return nil, err
  end
  local access_key = assert(sobject.custom_metadata['AccessKey'])
  local secret_key = sobject:export().value:bytes()
  local session_token = ''

  local role_arn = sobject.custom_metadata["RoleArn"]
  if role_arn ~= nil and role_arn ~= "" then
   local session_created = sobject.custom_metadata["TokenCreated"]
  if session_created ~= nil then
    local last_expiry = tonumber(session_created)
    local session_created_time = Time.at(last_expiry):fmt("%Y-%m-%d %H:%M:%S")  -- Format session creation time

    -- Calculate session expiration time
    local session_expiry = Time.at(last_expiry + session_ttl):fmt("%Y-%m-%d %H:%M:%S")  -- Format session expiry time

    -- Check if the session is still valid
    local time_now = Time.now_insecure():unix_epoch_seconds()
    if time_now < (last_expiry + session_ttl) then
      -- Renew session if needed
      session_token = secret_key:sub(41)
      secret_key = secret_key:sub(1, 40)
    end
  end
    
    if session_token == "" then -- read new token
      return nil, "Invalid session. Renew security token with assumerole."
    end
  end

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
  local headers = { ["X-Amz-Date"] = amzdate, ['X-Amz-Target'] = amzTarget, ['Content-Type'] = content_type, ['Authorization'] = authorization_header}
  if session_token ~= nil and session_token ~= "" then
    headers['X-Amz-Security-Token'] = session_token
  end
  local request_url = endpoint .. '?' .. canonical_querystring

  local response, err = request { method = method, url = request_url, headers = headers, body = request_body }

  if response == nil or err ~= nil then
    return nil, err
  end

  if response.status ~= 200 then
    if response.body ~= nil then
      local error_message = json.decode(response.body)
      return nil, error_message
    end
    return nil, response
  end

  local decoded_response, decode_err = json.decode(response.body)
  if decoded_response == nil then
    return nil, decode_err
  end

  return decoded_response, err
end

function generate_client_request_token()
  local chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  local tokenLength = 32
  local token = {}
  for i = 1, tokenLength do
      local rand = math.random(#chars)
      table.insert(token, chars:sub(rand, rand))
  end
  return table.concat(token)
end

-- Helper function to generate a UUID-type value
function uuid()
  local template ='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
  return string.gsub(template, '[xy]', function (c)
      local v = (c == 'x') and math.random(0, 0xf) or math.random(8, 0xb)
      return string.format('%x', v)
  end)
end

-- Function to create a new secret in AWS KMS via Fortanix DSM

function aws_create_secret(secret_id, aws_secret_name, secret_value)
    -- Fetch the secret object to get the region
    local sobject, err = Sobject { id = secret_id }
    if not sobject or err then
        return nil, "Failed to retrieve secret: " .. (err or "Unknown error")
    end

    local region = sobject.custom_metadata['Region']
    if not region then
        return nil, "Region not configured for this secret. Please set the region first."
    end

    -- Generate a client request token (UUID-type)
    local clientRequestToken = generate_client_request_token()

    -- Format the request body with the necessary information
    local request_body = {
        Name = aws_secret_name,
        ClientRequestToken = clientRequestToken,
        SecretString = secret_value
    }

    -- Use the aws_request function to make the API call with the region
    local response, err = aws_request(secret_id, "secretsmanager.CreateSecret", json.encode(request_body), "POST", region)

    if err ~= nil or (response and response.status ~= 200) then
        return {result = response, error = err}
    end

    return {result = json.decode(response.body), error = nil, message = 'AWS Secret created successfully'}
end

-- Function to list all secrets in AWS Secrets Manager with pagination and convert dates
function aws_list_secrets(secret_id)
    local sobject, err = Sobject { id = secret_id }
    if not sobject or not sobject.custom_metadata then
        return nil, "Failed to retrieve secret or metadata: " .. (err or "Metadata is missing")
    end

    local region = sobject.custom_metadata['Region']
    if not region then
        return nil, "Region not configured for this secret. Please set the region first."
    end

    local results = {}
    local next_token = nil
    repeat
        local request_body = next_token and { NextToken = next_token } or {}
        local response, err = aws_request(secret_id, "secretsmanager.ListSecrets", json.encode(request_body), "POST", region)
        if err then
            return nil, "Error listing secrets: " .. err
        end

        local secrets = response.SecretList
        for _, secret in ipairs(secrets) do
            -- Convert timestamps to human-readable format
            if secret.CreatedDate then
                secret.CreatedDate = gmtime(secret.CreatedDate)
            end
            if secret.LastChangedDate then
                secret.LastChangedDate = gmtime(secret.LastChangedDate)
            end
            if secret.LastAccessedDate then
                secret.LastAccessedDate = gmtime(secret.LastAccessedDate)
            end
            table.insert(results, secret)
        end
        next_token = response.NextToken
    until not next_token

    return results, nil
end

-- Function to list all secret versions in AWS Secrets Manager with pagination
function aws_list_secret_versions(secret_id, secret_name)
    local sobject, err = Sobject { id = secret_id }
    if not sobject or err then
        return nil, "Failed to retrieve secret: " .. (err or "Unknown error")
    end

    local region = sobject.custom_metadata['Region']
    if not region then
        return nil, "Region not configured for this secret. Please set the region first."
    end

    local results = {}
    local next_token = nil

    repeat
        local request_body = { SecretId = secret_name }
        if next_token then
            request_body.NextToken = next_token
        end

        local response, err = aws_request(secret_id, "secretsmanager.ListSecretVersionIds", json.encode(request_body), "POST", region)
        if err then
            return nil, err
        end

        local versions = response.Versions
        for _, version in ipairs(versions) do
            table.insert(results, version)
        end

        next_token = response.NextToken
    until not next_token

    return results, nil
end

-- Function to import all secrets with pagination
function import_all_secrets_into_dsm(secret_id)
    local results = {}
    local next_token_secrets = nil

    repeat
        -- Import secrets
        local secrets, err_secrets = aws_list_secrets(secret_id)
        if err_secrets then
            return { result = nil, error = "Error fetching secrets: " .. extractError(err_secrets) }
        end

        -- Check if secrets is a table before attempting to iterate
        if type(secrets) == "table" then
            for _, secret in ipairs(secrets) do
                -- Import secret versions
                local next_token_versions = nil
                repeat
                    local versions, err_versions = aws_list_secret_versions(secret_id, secret.ARN)
                    if err_versions then
                        table.insert(results, { secret_name = secret.Name, error = "Error fetching versions: " .. extractError(err_versions) })
                    else
                        -- Check if versions is a table before attempting to iterate
                        if type(versions) == "table" then
                            for _, version in ipairs(versions) do
                                local result = import_secret_version_into_dsm(secret_id, secret.Name, version.VersionId, version.VersionStages[1])
                                if result and result.error then
                                    table.insert(results, { secret_name = secret.Name, version = version.VersionId, stage = version.VersionStages[1], error = extractError(result.error) })
                                else
                                    table.insert(results, { secret_name = secret.Name, version = version.VersionId, stage = version.VersionStages[1], message = "Secret imported successfully" })
                                end
                            end
                        end
                    end
                    next_token_versions = versions and versions.NextToken
                until not next_token_versions
            end
        end

        -- Check if there are more secrets to retrieve
        next_token_secrets = secrets and secrets.NextToken
    until not next_token_secrets

    return { message = "All secrets imported successfully", result = results }
end

-- Function to extract an error message from error objects
function extractError(err)
    if type(err) == 'table' then
        -- Assuming the error object might contain a message key
        return err.message or err.error or "Unknown error"
    else
        return tostring(err)
    end
end

-- Function to import one secret in DSM
function import_secret_version_into_dsm(secret_id, aws_secret_name, aws_secret_version, aws_version_stage)
    -- Validate input parameters
    if secret_id == nil or aws_secret_name == nil or aws_secret_version == nil then
        return { result = nil, error = "Invalid input parameters" }
    end

    -- Construct the request body as a JSON object
    local request_body = {
        SecretId = aws_secret_name,
        VersionStage = aws_version_stage,
        VersionId = aws_secret_version
    }

    -- Convert the request body to JSON string
    local request_body_json = json.encode(request_body)

    -- Make the API request to AWS Secrets Manager
    local response, err = aws_request(secret_id, "secretsmanager.GetSecretValue", request_body_json, "POST")
    if err then
        return { result = nil, error = err, message = 'Could not obtain secret from AWS Secret Manager' }
    end

    -- Check if the response contains the expected properties
    if type(response) == "table" and response.SecretString then
        local secretPair = json.decode(response.SecretString)
        local value = response.SecretString  -- Default to the raw string if decoding fails

        if type(secretPair) == "table" then
            -- Assuming the secretPair table contains key-value pairs and we take the value of the first pair
            for _, v in pairs(secretPair) do
                value = v
                break
            end
        end

        -- Import the secret into DSM
        local sobject, import_err = Sobject.import { name = aws_secret_name .. '/' .. aws_secret_version, obj_type = 'SECRET', value = Blob.from_bytes(value) }
        if sobject == nil or import_err then
            return { result = nil, error = import_err or "Failed to import secret into DSM" }
        end

        return { secret_name = sobject.name, message = "Secret imported successfully", error = nil }
    else
        return { result = nil, error = "Unexpected response format or missing 'SecretString' in response" }
    end
end

-- Function to extract a error message from error objects
function extractError(err)
    if type(err) == 'table' then
        -- Assuming the error object might contain a message key
        return err.message or err.error or "Unknown error"
    else
        return tostring(err)
    end
end

-- Function to delete a secret in AWS Secrets Manager
function aws_delete_secret(secret_id, secret_name)
    -- Format the request body with the secret name or ARN
    local request_body = json.encode({SecretId = secret_name})

    -- Call aws_request to handle the deletion, it will fetch the region from the secret's metadata
    local response, err = aws_request(secret_id, "secretsmanager.DeleteSecret", request_body, "POST")
    if err then
        return nil, "Error deleting secret: " .. tostring(err)
    end

    -- Convert timestamps to human-readable format if they exist
    if response.DeletionDate then
        response.DeletionDate = gmtime(response.DeletionDate)
    end
    if response.LastChangedDate then
        response.LastChangedDate = gmtime(response.LastChangedDate)
    end

    return response, nil
end

-- Function to rotate a secret in AWS Secrets Manager

function aws_rotate_secret(secret_id, secret_name, new_secret_value)
    -- Generate a unique client request token for idempotency
    local client_request_token = generate_client_request_token()

    -- Format the request body with the new secret value
    local request_body = json.encode({
        SecretId = secret_name,
        SecretString = new_secret_value,
        ClientRequestToken = client_request_token
    })

    -- Call aws_request with the action to rotate the secret
    local response, err = aws_request(secret_id, "secretsmanager.UpdateSecret", request_body, "POST")
    return response, err
end

-- Function to restore a deleted a secret in AWS Secrets Manager

function aws_restore_secret(secret_id, secret_name)
    -- Format the request body with the secret name or ARN
    local request_body = json.encode({SecretId = secret_name})
    local response, err = aws_request(secret_id, "secretsmanager.RestoreSecret", request_body, "POST")
    return response, err
end

-- Function to Export a secret from DSM to AWS Secret Manager
function import_secret_into_aws(secret_id, aws_secret_name, dsm_secret_name)
    -- Find the secret in DSM
    local sobject, err = Sobject {name = dsm_secret_name}
    if not sobject or err then
        return {result = nil, error = "Import operation failed: " .. tostring(err)}
    end

    local value = sobject:export().value:bytes()

    local request_body = {
        ["SecretString"] = value,
        ["Name"] = aws_secret_name,
        ["ClientRequestToken"] = uuid()  -- Ensuring idempotency with a unique token
    }

    local response, err = aws_request(secret_id, "secretsmanager.CreateSecret", json.encode(request_body), "POST")
    if err then
        -- Instead of directly using `err`, check the format and log appropriately
        return {result = nil, error = "AWS Secret creation request failed: " .. (type(err) == "table" and err.message or tostring(err))}
    end

    if not response then
        return {result = nil, error = "No response from AWS"}
    end

    -- Check if the response has the expected fields
    if response.ARN and response.Name and response.VersionId then
        return {result = response, message = 'AWS Secret created successfully'}
    else
        return {result = response, error = "Unexpected response format from AWS Secret creation"}
    end
end

function check(input)
   if input.secret_id ~= nil then
  local sobject, err = Sobject { id = input.secret_id }
  if sobject == nil or err ~= nil then
    err = "AWS credential is not configured or incorrect. Please run cofigure operation."
    return nil, err
  end
  if sobject.custom_metadata == nil then
      err = "AWS credential is not configured or incorrect. Please run cofigure operation."
    return nil, err
  end
  end
end

function run(input)
   if input.operation == "configure" then
    local name = Blob.random { bits = 64 }:hex()
    if input.name then name = input.name end
    if not input.secret_key or not input.access_key or not input.region then
        return nil, "Missing required parameters (secret_key, access_key, or region)"
    end
    local secret = assert(Sobject.import{
        name = name, 
        obj_type = "SECRET",
        value = Blob.from_bytes(input.secret_key),
        custom_metadata = {
            AccessKey = input.access_key,
            Region = input.region
        }
    })
    return {secret_id = secret.kid, message = "Configuration successful, region set: " .. input.region}

  
  elseif input.operation == "list" then
        return aws_list_secrets(input.secret_id, region)
 

  elseif input.operation == "create" then
        local secret_id = input.secret_id
        local aws_secret_name = input.aws_secret_name
        local secret_value = input.secret_value

        if not secret_id or not aws_secret_name or not secret_value then
            return { result = nil, error = "Missing required parameters for secret creation" }
        end

        return aws_create_secret(secret_id, aws_secret_name, secret_value)
    
  elseif input.operation == "list_versions" then
        local secret_id = input.secret_id
        local secret_name = input.name  -- Ensure you have the correct secret name from input

        if not secret_id or not secret_name then
            return { result = nil, error = "Missing required parameters for listing versions" }
        end

        return aws_list_secret_versions(secret_id, secret_name)

  elseif input.operation == "import_all_secrets" then
    local secret_id = input.secret_id
    if not secret_id then
      return { result = nil, error = "Secret ID must be provided for import_all_secrets operation" }
  end
    return import_all_secrets_into_dsm(secret_id)
  
  elseif input.operation == "restore" then
        if not input.name then
            return nil, "Missing 'name' for restore operation."
        end
        local resp, err = aws_restore_secret(input.secret_id, input.name)
        if resp == nil then return err end
        return resp
    
  elseif input.operation == "export" then
    local dsm_secret_name = input.dsm_secret_name
    local aws_secret_name = input.aws_secret_name
    local secret_id = input.secret_id

    if not dsm_secret_name or not aws_secret_name or not secret_id then
      return { result = nil, error = "Missing required parameters for export operation" }
    end

    return import_secret_into_aws(secret_id, aws_secret_name, dsm_secret_name)

    
  elseif input.operation == "import_from_aws" then
        -- Import a secret version from AWS Secret Manager into DSM
        local secret_id = input.secret_id -- The secret ID for authentication
        local aws_secret_name = input.aws_secret_name -- The name of the AWS secret
        local aws_secret_version = input.aws_secret_version -- The version of the AWS secret
        local aws_version_stage = input.aws_version_stage -- The version of the AWS secret

        local result, err = import_secret_version_into_dsm(secret_id, aws_secret_name, aws_secret_version, aws_version_stage)
        if result == nil then
            return err
        else
            return result
    end
    
  elseif input.operation == "delete" then
        -- Assume input.name is the name or ARN of the secret to delete
        local secret_name = input.name
        if not secret_name then
            return nil, "Secret name or ARN must be provided for delete operation"
        end
        -- Delete the secret using the modified delete function
        local resp, err = aws_delete_secret(input.secret_id, secret_name)
        if err then
            return nil, err
        end
        return resp
    
  elseif input.operation == "rotate" then
        if not input.secret_name or not input.new_secret_value then
            return nil, "Missing 'secret_name' or 'new_secret_value' for rotate operation."
        end
        local resp, err = aws_rotate_secret(input.secret_id, input.secret_name, input.new_secret_value)
        if resp == nil then
            return nil, err
        end
        return {message = "Secret rotated successfully.", response = resp}
    else
    return nil, "Unsupported operation"
  end
end

