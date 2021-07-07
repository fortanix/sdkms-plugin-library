-- Name: Google Cloud BYOK
-- Version: 1.0
-- Description:## Short Description
-- This plugin implements the Bring your own key (BYOK) model for Google cloud. Using this plugin you can keep your key inside Fortanix Self-Defending KMS and use BYOK features of Google Cloud KMS.
-- ### ## Introduction
-- The cloud services provide many advantages but the major disadvantage of cloud providers has been security because physically your data resides with the cloud provider. To keep data secure in a cloud provider environment, enterprises use encryption. So securing their encryption keys become significantly important. Bring Your Own Key (BYOK) allows enterprises to encrypt their data and retain control and management of their encryption keys. This plugin provides an implementation to use the Google cloud BYOK model.
-- ## Requirement
-- Fortanix Self-Defending KMS Version >= 3.17.1330
-- ## Use cases 
-- The plugin can be used to
-- 
-- - Push Fortanix Self-Defending KMS key in Google Cloud KMS
-- - List Fortanix Self-Defending KMS Google Cloud BYOK key
-- - Rotate Fortanix Self-Defending KMS Google Cloud BYOK key
-- - Disable Google Cloud BYOK key from Fortanix Self-Defending KMS
-- - Enable Google Cloud BYOK key from Fortanix Self-Defending KMS
-- - Delete Google Cloud BYOK key from Fortanix Self-Defending KMS
-- - Reimport key material from Fortanix Self-Defending KMS to Google Cloud CMK
-- 
-- 
-- ## Setup
-- 
-- - Log in to Google Cloud portal
-- - Create Google Cloud KMS Service Account and Secret Key
-- - Create Google Cloud IAM Role for Cloud KMS Admin
-- - Attach IAM Role to Service Account
-- 
-- ## Input/Output JSON object format
-- 
-- ### Configure operation
-- 
-- This operation configures Google Cloud Service Account secret Key in Fortanix Self-Defending KMS and returns a UUID. -- You need to pass this UUID for other operations. This is a one time process.
-- 
-- #### Parameters 
-- 
-- * `operation`: The operation which you want to perform. A valid value is `configure`.
-- * `secret_key`: Google Cloud secret key containing the type, project, client_email and private_key
-- 
-- #### Example
-- 
-- Input JSON
-- ```
-- {
--   "operation": "configure",
--   "location": "us-east1",
--   "key_ring": "gcp-keyring",
--   "secret_key": {
--     "type": "service_account",
--     "project_id": "project-id-102203",
--     "client_email": "sdkms-byok@project-id-102203.iam.gserviceaccount.com",
--     "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkggSiAgEAAdIk2bywgHRaKg==\n-----END PRIVATE KEY-----\n"
--   }
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
-- This operation will create an AES-256 key in Fortanix Self-Defending KMS and import it in Google Cloud KMS.
-- 
-- #### Parameters 
-- 
-- * `operation`: The operation which you want to perform. A valid value is `create`.
-- * `name`: Name of the key
-- * `secret_id`: The response of `configuration` operation. 
-- * `location`: Optional. Region or location. Example: global or us-east1.
-- * `key_ring`: Optional. Name of Google Cloud KMS key ring.
-- * `disable_previous`: true|false. Previous key version state change.
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
--   "labels": { "source": "fortanix-byok" }
-- }
-- ```
-- 
-- Output JSON
-- ```
-- {
--   "creator": {
--     "plugin": "37d99d30-85cc-43fb-aa03-b12d25def766"
--   },
--   "kid": "c48db54f-075e-4500-9900-715eb74c5349",
--   "acct_id": "0491fa2d-0c59-4daf-b293-8859c7d491d0",
--   "custom_metadata": {
--     "GCP_KEY_ID": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key",
--     "GCP_CREATED": "2020-09-21T20:58:15.849005292Z",
--     "GCP_KEY_VERSION": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key/-- cryptoKeyVersions/1",
--     "GCP_UPDATED": "2020-09-21T20:52:12.282941162Z"
--   },
--   "aes": {
--     "random_iv": null,
--     "key_sizes": null,
--     "cipher_mode": null,
--     "fpe": null,
--     "iv_length": null,
--     "tag_length": null
--   },
--   "kcv": "a90519",
--   "activation_date": "20200921T215621Z",
--   "key_size": 256,
--   "key_ops": [
--     "ENCRYPT",
--     "DECRYPT",
--     "EXPORT",
--     "APPMANAGEABLE"
--   ],
--   "group_id": "0f1ffedd-9a23-4dc8-9a47-952e50bb1b71",
--   "lastused_at": "19700101T000000Z",
--   "never_exportable": false,
--   "obj_type": "AES",
--   "enabled": true,
--   "compliant_with_policies": true,
--   "origin": "FortanixHSM",
--   "name": "test-key",
--   "created_at": "20200921T215621Z",
--   "public_only": false,
--   "state": "Active"
-- }
-- ```
-- 
-- ### List operation
-- 
-- This operation will list all the BYOK keys from a Google Cloud KMS key ring.
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
--   "cryptoKeys": [
--     {
--       "createTime": "2020-09-21T02:26:48.718637503Z",
--       "versionTemplate": {
--         "protectionLevel": "SOFTWARE",
--         "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"
--       },
--       "purpose": "ENCRYPT_DECRYPT",
--       "name": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/Fortanix-GCP-BYOKey",
--       "labels": {
--         "source": "fortanix-byok"
--       }
--     },
--     {
--       "labels": {
--         "source": "fortanix-byok"
--       },
--       "createTime": "2020-09-21T20:58:15.849005292Z",
--       "primary": {
--         "importTime": "2020-09-21T21:20:25.960522434Z",
--         "protectionLevel": "SOFTWARE",
--         "importJob": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/importJobs/-- byok-ftx-plugin-1600721534",
--         "state": "ENABLED",
--         "name": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key/cryptoKeyVersions/4",
--         "createTime": "2020-09-21T21:20:25.935360774Z",
--         "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"
--       },
--       "name": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key",
--       "purpose": "ENCRYPT_DECRYPT",
--       "versionTemplate": {
--         "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
--         "protectionLevel": "SOFTWARE"
--       }
--     }
--   ],
--   "totalSize": 2
-- }
-- ```
-- 
-- ### Get operation
-- 
-- This operation will retrieve a specific BYOK key from Google Cloud KMS.
-- 
-- #### Parameters 
-- 
-- * `operation`: The operation which you want to perform. A valid value is `get`.
-- * `secret_id`: The response of `configuration` operation. 
-- * `name`: Name of the key  
-- 
-- #### Example
-- 
-- Input JSON
-- ```
-- {
--   "operation": "get", 
--   "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
--   "name": "test-key",
-- }
-- ```
-- 
-- Output JSON
-- ```
-- {
--   "primary": {
--     "protectionLevel": "SOFTWARE",
--     "importTime": "2020-09-21T21:20:25.960522434Z",
--     "createTime": "2020-09-21T21:20:25.935360774Z",
--     "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
--     "name": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key/cryptoKeyVersions/4",
--     "importJob": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/importJobs/byok-ftx-plugin-1600721534",
--     "state": "ENABLED"
--   },
--   "labels": {
--     "source": "fortanix-byok"
--   },
--   "createTime": "2020-09-21T20:58:15.849005292Z",
--   "purpose": "ENCRYPT_DECRYPT",
--   "versionTemplate": {
--     "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
--     "protectionLevel": "SOFTWARE"
--   },
--   "name": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key"
-- }
-- ```
-- 
-- ### Rotate operation
-- 
-- This operation will rotate a key in Fortanix Self-Defending KMS as well as in Google Cloud KMS.
-- 
-- #### Parameters 
-- 
-- * `operation`: The operation which you want to perform. A valid value is `rotate`.
-- * `secret_id`: The response of `configuration` operation. 
-- * `name`: Name of the key  
-- 
-- #### Example
-- 
-- Input JSON
-- ```
-- {
--   "operation": "rotate", 
--   "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
--   "name": "test-key",
-- }
-- ```
-- 
-- Output JSON
-- ```
-- {
--   "creator": {
--     "plugin": "37d99d30-85cc-43fb-aa03-b12d25def766"
--   },
--   "kid": "c48db54f-075e-4500-9900-715eb74c5349",
--   "acct_id": "0491fa2d-0c59-4daf-b293-8859c7d491d0",
--   "custom_metadata": {
--     "GCP_KEY_ID": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key",
--     "GCP_CREATED": "2020-09-21T20:58:15.849005292Z",
--     "GCP_KEY_VERSION": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key/-- cryptoKeyVersions/2",
--     "GCP_UPDATED": "2020-09-21T21:56:22.663641162Z"
--   },
--   "aes": {
--     "random_iv": null,
--     "key_sizes": null,
--     "cipher_mode": null,
--     "fpe": null,
--     "iv_length": null,
--     "tag_length": null
--   },
--   "kcv": "a90519",
--   "activation_date": "20200921T215621Z",
--   "key_size": 256,
--   "key_ops": [
--     "ENCRYPT",
--     "DECRYPT",
--     "EXPORT",
--     "APPMANAGEABLE"
--   ],
--   "group_id": "0f1ffedd-9a23-4dc8-9a47-952e50bb1b71",
--   "lastused_at": "19700101T000000Z",
--   "never_exportable": false,
--   "obj_type": "AES",
--   "enabled": true,
--   "compliant_with_policies": true,
--   "origin": "FortanixHSM",
--   "name": "test-key",
--   "created_at": "20200921T215621Z",
--   "public_only": false,
--   "state": "Active"
-- }
-- ```
-- 
-- ### Disable operation
-- 
-- This operation will disable a Google Cloud KMS key.
-- 
-- #### Parameters 
-- 
-- * `operation`: The operation which you want to perform. A valid value is `disable`.
-- * `secret_id`: The response of `configuration` operation. 
-- * `name`: Name of the key  
-- 
-- #### Example
-- 
-- Input JSON
-- ```
-- {
--   "operation": "disable", 
--   "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
--   "name": "test-key",
-- }
-- ```
-- 
-- Output JSON
-- ```
-- {
--   "protectionLevel": "SOFTWARE",
--   "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
--   "createTime": "2020-09-21T21:20:25.935360774Z",
--   "name": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key/cryptoKeyVersions/4",
--   "importJob": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/importJobs/byok-ftx-plugin-1600721534",
--   "importTime": "2020-09-21T21:20:25.960522434Z",
--   "state": "DISABLED"
-- }
-- ```
-- 
-- ### Enable operation
-- 
-- This operation will enable a Google Cloud KMS key that's disabled.
-- 
-- #### Parameters 
-- 
-- * `operation`: The operation which you want to perform. A valid value is `enable`.
-- * `secret_id`: The response of `configuration` operation. 
-- * `name`: Name of the key  
-- 
-- #### Example
-- 
-- Input JSON
-- ```
-- {
--   "operation": "enable", 
--   "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
--   "name": "test-key",
-- }
-- ```
-- 
-- Output JSON
-- ```
-- {
--   "importJob": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/importJobs/byok-ftx-plugin-1600721534",
--   "protectionLevel": "SOFTWARE",
--   "importTime": "2020-09-21T21:20:25.960522434Z",
--   "name": "projects/fortanix/locations/us-east1/keyRings/gcp-keyring/cryptoKeys/test-key/cryptoKeyVersions/4",
--   "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
--   "createTime": "2020-09-21T21:20:25.935360774Z",
--   "state": "ENABLED"
-- }
-- ```
-- ### Release Notes
-- - Initial Release

--[[
-- Google Cloud BYOK from Fortanix Self-Defending KMS
-- Revision: 1.1
-- Date: Sep 30 2020

--configure
{
  "operation": "configure",
  "location": "us-east1",
  "key_ring": "POV-demo-BYOK",
  "secret_key": {
    "type": "service_account",
    "project_id": "fortanix",
    "client_email": "ekms-test@fortanix.iam.gserviceaccount.com",
    "private_key": "a886ae6a-c105-4c20-abf1-835f6f49b835"
  }
}
{
  "operation": "configure",
  "location": "us-east1",
  "key_ring": "POV-demo-BYOK",
  "secret_key": {
    "type": "service_account",
    "project_id": "fortanix",
    "client_email": "ekms-test@fortanix.iam.gserviceaccount.com",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAk2bywgHRaKg==\n-----END PRIVATE KEY-----\n"
  }
}

--list
{
  "operation": "list",
  "secret_id": "f8834855-6dd4-4914-97ef-f0ca9774f8b8",
  "location": "us-east1",
  "key_ring": "POV-demo-BYOK"
}

-- create
{
  "operation": "create",
  "secret_id": "f8834855-6dd4-4914-97ef-f0ca9774f8b8",
  "location": "us-east1",
  "key_ring": "POV-demo-BYOK",
  "name": "target-GCP-BYOkey",
  "disable_previous": true,
  "labels": { "source": "fortanix-byok", "env": "sandbox" }
}

-- rotate
{
  "operation": "rotate",
  "secret_id": "f8834855-6dd4-4914-97ef-f0ca9774f8b8",
  "location": "us-east1",
  "key_ring": "POV-demo-BYOK",
  "disable_previous": false
}

-- enable
{
  "operation": "enable",
  "secret_id": "f8834855-6dd4-4914-97ef-f0ca9774f8b8",
  "location": "us-east1",
  "key_ring": "POV-demo-BYOK",
  "name": "target-GCP-BYOkey"
}

-- disable
{
  "operation": "disable",
  "secret_id": "f8834855-6dd4-4914-97ef-f0ca9774f8b8",
  "location": "us-east1",
  "key_ring": "POV-demo-BYOK",
  "name": "target-GCP-BYOkey"
}

--]]

local service = 'cloudkms'
local host = 'googleapis.com'
local content_type = 'application/json'
local project = ''
local session_token = ''
local import_job_id = 'byok-ftx-plugin-'
-----------------------------------------------------------------------------------

local function replace(str, what, with)
    what = string.gsub(what, "[%(%)%.%+%-%*%?%[%]%^%$%%]", "%%%1") -- escape pattern
    with = string.gsub(with, "[%%]", "%%%%") -- escape replacement
    return string.gsub(str, what, with)
end

function configure_secret(secret_key, location, key_ring)
  if type(secret_key) ~= 'table' or secret_key.private_key == nil then
    return {result = import_params, error = err, message = "Configure BYOK needs a secret private key"}
  end
  local name = Blob.random { bits = 64 }:hex()
  if string.sub(secret_key.private_key, 6, 22) == "BEGIN PRIVATE KEY" then
    local pkey = secret_key.private_key:gsub('\n', '')
    pkey = pkey:gsub('-', '')
    pkey = pkey:gsub('BEGIN PRIVATE KEY', '')
    pkey = pkey:gsub('END PRIVATE KEY', '')
    local gcp_sa_key = assert(Sobject.import{ name = name, obj_type = "RSA", 
        value = Blob.from_base64(pkey)})
    secret_key.private_key = gcp_sa_key.kid
    name = Blob.random { bits = 64 }:hex() -- reset name
  else
    -- verify private key exists
    assert(Sobject {kid = secret_key.private_key})
  end
  local gcp_sa_secret = assert(Sobject.import{ name = name, obj_type = "SECRET", 
      value = Blob.from_bytes(json.encode(secret_key)),
      custom_metadata = {
        ["Project"] = secret_key.project_id, 
        ["Location"] = location, 
        ["KeyRing"] = key_ring
      }})
  return gcp_sa_secret
end

function sign_jwt(key, msg)
  assert(type(msg) == 'string')
  local gcp_secret_key = assert(Sobject { kid = key })
  local sign_response = assert(gcp_secret_key:sign { data = Blob.from_bytes(msg), hash_alg = 'SHA256' })
  local signature = sign_response.signature:base64()
  signature = signature:gsub('/', '_'):gsub('+', '-'):gsub('=', '')
  return signature
end

function gcp_get_token(issuer, jkid)
  local time = Time.now_insecure()

  -- generate a JWT and sign it
  local jwt_hdr = '{"alg":"RS256","typ":"JWT"}'
  local jwt_body = {}
  jwt_body["iss"] = issuer
  jwt_body["scope"] = 'https://www.'..host..'/auth/'..service
  jwt_body["aud"] = 'https://www.'..host..'/oauth2/v4/token'
  jwt_body["iat"] = time:unix_epoch_seconds()
  jwt_body["exp"] = time:unix_epoch_seconds()+30

  --if true then return json.encode(jwt_body) end
  local jwt_payload = Blob.from_bytes(jwt_hdr):base64():gsub('/', '_'):gsub('+', '-'):gsub('=', '')..
    "."..Blob.from_bytes(json.encode(jwt_body)):base64():gsub('/', '_'):gsub('+', '-'):gsub('=', '')

  local jwt_signature = sign_jwt(jkid, jwt_payload)
  local jwt_signed = jwt_payload.."."..jwt_signature
    
  --if true then return jwt_body["scope"] end --endpoint end
  
  --local authorization_header = 'Bearer ' .. access_token
  local headers = { ['Content-Type'] = content_type }
  local request_body = json.encode({grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion = jwt_signed})
  
  response, err = request { method = "POST", url = jwt_body["aud"], headers = headers, body=request_body }
  if response.status ~= 200 then
    return nil, response
  end
  return json.decode(response.body), err

end

function gcp_session(secret_id)
  if session_token ~= "" then
    return session_token
  end
  local sobject, err = Sobject { id = secret_id }
  if sobject == nil or err ~= nil then
    err = "GCP credential is not configured or incorrect. Please run cofigure operation."
    return nil, err
  end
  -- courtesy checks
  if sobject.custom_metadata == nil or sobject.custom_metadata["Project"] == nil then
      err = "GCP credential is not configured or incorrect. Please run cofigure operation."
    return nil, err
  end
  
  local secret_key_blob = sobject:export().value:bytes()
  local secret_key = json.decode(secret_key_blob)
  if secret_key.type == "service_account" then
    token_json = gcp_get_token(secret_key.client_email, secret_key.private_key) -- cache, sobject.custom_metadata["Project"])
    session_token = token_json.access_token
  else
    session_token = secret_key.access_token
  end
  return session_token
end

function gcp_request(secret_id, location, key_ring, api_target, request_body, method)
  local access_token, err = gcp_session(secret_id)
  if access_token == nil then
    return { result = access_token, error = err, message = "Cannot fetch access token, please check the secret_id"}
  end
  --if true then return access_token end --endpoint end
  
  local endpoint = 'https://'..service..'.'..host..
    "/v1/projects/"..project..
    "/locations/"..location..
    "/keyRings/"..key_ring
    
  local authorization_header = 'Bearer ' .. access_token
  local headers = { ['Content-Type'] = content_type, ['Authorization'] = authorization_header}
  local request_url = endpoint .. '/' .. api_target
  
  response, err = request { method = method, url = request_url, headers = headers, body=request_body }
  if response.status ~= 200 then
    return nil, response
  end
  return json.decode(response.body), err
end

function gcp_list_keys(secret_id, location, key_ring, key_name)
  local filter = "/"
  if key_name ~= nil and key_name ~= "" then
    filter = filter..key_name
  else
    filter = ""
  end
  local response, err = gcp_request(secret_id ,location, key_ring, "cryptoKeys"..filter, "{}", "GET")
  if response ~= nil then
    return response, nil
  end
  return response, err
end

function gcp_create_key(secret_id, location, key_ring, key_name, labels)
  local gcp_key, err = gcp_list_keys(secret_id, location, key_ring, key_name)
  if gcp_key ~= nil then
    return gcp_key, nil
  end
  assert(type(key_name) == 'string')
  local key_id = "cryptoKeyId="..key_name
  local skip_version = "&skipInitialVersionCreation=true"
  local payload = {}
  if labels ~= nil and type(labels) == "table" then
    payload.labels = labels
  else
    payload.labels = {}
    payload.labels.source = "fortanix-byok"
  end
  payload.purpose = "ENCRYPT_DECRYPT"
  local response, err = gcp_request(secret_id ,location, key_ring, "cryptoKeys?"..key_id..skip_version, json.encode(payload), "POST")
  return response, err
end

function gcp_create_import_job(secret_id, location, key_ring, job_name)
  local active = "filter=state=ACTIVE"
  local response, err = gcp_request(secret_id ,location, key_ring, "importJobs?"..active, "{}", "GET")
  if response ~= nil and response.importJobs ~= nil then
    return response.importJobs, nil
  end
  local job_id = "importJobId="..job_name
  assert(type(job_id) == 'string')  
  local payload = {}
  payload.importMethod = "RSA_OAEP_3072_SHA1_AES_256" -- alt: RSA_OAEP_4096_SHA1_AES_256
  payload.protectionLevel = "SOFTWARE" -- alt: HSM
  local response, err = gcp_request(secret_id ,location, key_ring, "importJobs?"..job_id, json.encode(payload), "POST")
  if err == nil then
    -- need to get job to read publicKey since create returns job in state: PENDING_CREATION
    local response, err = gcp_request(secret_id ,location, key_ring, "importJobs?"..active, "{}", "GET")
    if response ~= nil and response.importJobs ~= nil then
      return response.importJobs, nil
    end
  end
  return response, err
end

function wrap_keys_for_import(secret_id, import_job, target_key)
  -- import GCP Public key
  local import_pub_pem = import_job.publicKey.pem:gsub('\n',''):gsub('-',''):gsub('BEGIN PUBLIC KEY',''):gsub('END PUBLIC KEY','')
  
  local import_pub_key = assert(Sobject.import { obj_type = 'RSA', transient = true, key_size = 3072, 
    value = Blob.from_base64(import_pub_pem), 
    key_ops = {'ENCRYPT', 'DECRYPT', 'WRAPKEY', 'UNWRAPKEY', 'APPMANAGEABLE', 'EXPORT'} })
  -- Wrap a temp AES key with Import Pub Key
  local import_tmp_key = assert(Sobject.create { obj_type = 'AES', transient = true, key_size = 256, 
      key_ops = {'ENCRYPT', 'DECRYPT', 'WRAPKEY', 'UNWRAPKEY', 'APPMANAGEABLE', 'EXPORT'} })
  
  wrapped_tmp_aes = assert(import_pub_key:wrap { subject = import_tmp_key, mode = 'OAEP_MGF1_SHA1' })
  wrapped_target = assert(import_tmp_key:wrap { subject = target_key, mode = 'KWP' })
  
  local rsaaes_wrapped_key = wrapped_tmp_aes.wrapped_key..wrapped_target.wrapped_key
  return rsaaes_wrapped_key:base64()
  -- https://cloud.google.com/kms/docs/importing-a-key#importing_a_manually-wrapped_key
end

function gcp_import_key(secret_id, location, key_ring, key_name, gcp_key, gcp_import_job, rsaaes_wrapped_key)
  local payload = {}
  payload.algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION" -- alt: 
  payload.importJob = gcp_import_job.name
  payload.rsaAesWrappedKey = rsaaes_wrapped_key
  
  local gcp_key_version_pending, err = gcp_request(secret_id ,location, key_ring, "cryptoKeys/"..key_name.."/cryptoKeyVersions:import", json.encode(payload), "POST")
  if gcp_key_version_pending ~= nil then
    -- gcp_key_version_pending changes state from PENDING_IMPORT to ENABLED
    -- local gcp_key_version, err = gcp_request(secret_id ,location, key_ring, key_name, "{}", "GET")
    if gcp_key_version_pending ~= nil then
      -- get the version ID for setting pirimary on the key itself
      local key_version_id =  replace(gcp_key_version_pending.name, gcp_key.name.."/cryptoKeyVersions/", "")
      local payload = {}
      payload.cryptoKeyVersionId = key_version_id
      local gcp_key, err = gcp_request(secret_id ,location, key_ring, "cryptoKeys/"..key_name..":updatePrimaryVersion", json.encode(payload), "POST")
      if gcp_key ~= nil then
        return gcp_key, nil
      end
    end
  end
  return gcp_key_version_pending, err
end

function gcp_toggle_key(secret_id, location, key_ring, key_name, gcp_key, desired_state)
  if gcp_key.primary then
    local key_version_id =  replace(gcp_key.primary.name, gcp_key.name.."/cryptoKeyVersions/", "")
    local api_target = "cryptoKeys/"..key_name.."/cryptoKeyVersions/"..key_version_id.."?updateMask=state"
    
    local payload = {}
    if gcp_key.primary.state == "ENABLED" or desired_state == "DISABLED" then
      payload.state = "DISABLED"
    else
      payload.state = "ENABLED"
    end
    local gcp_key_version_renewed, err = gcp_request(secret_id ,location, key_ring, api_target, json.encode(payload), "PATCH")
    return gcp_key_version_renewed, err
  end
end

function gcp_delete_key(secret_id, gcp_key)
  return "Deletion not allowed"
end

------------------------------------------------------------------------------------

function check(input)
  if input.location == nil then input.location = "" end
  if input.key_ring == nil then input.key_ring = "" end
  if input.secret_id ~= nil then
    local secret, err = Sobject { id = input.secret_id }
    if secret ~= nil then 
    	project = secret.custom_metadata['Project']
    end
    if (project == nil or project == "") and input.secret_key ~= nil then
      project = input.secret_key.project_id
    end
    if input.location == nil or input.location == "" then
      input.location = secret.custom_metadata['Location']
    end
    if input.location == nil or input.location == "" then input.location = 'us-east1' end -- alt: global
    if input.key_ring == nil or input.key_ring == "" then
      input.key_ring = secret.custom_metadata['KeyRing']
    end
  end
end

function run(input)

  if input.operation == "configure" then  
    local gcp_secret = configure_secret(input.secret_key, input.location, input.key_ring)
    return {secret_id = gcp_secret.kid}
    
  elseif input.operation == "list" then
    keys, err = gcp_list_keys(input.secret_id, input.location, input.key_ring)
    if keys == nil then
      return { result = keys, error = err, message = input.operation..": GCP BYOK list keys operation failed"}
    end
    return keys

  elseif input.operation == "get" then
    keys, err = gcp_list_keys(input.secret_id, input.location, input.key_ring, input.name)
    return keys, err

  elseif input.operation == "create" or input.operation == "rotate" then
    -- Create master key in SDKMS
    local target_key = Sobject { name = input.name }
    local tbr_target_key = Sobject { name = "ToBeRotated-"..input.name }
    if target_key == nil then
      target_key = assert(Sobject.create { obj_type = 'AES', key_size = 256, 
          name = input.name, key_ops = {'ENCRYPT', 'DECRYPT', 'APPMANAGEABLE', 'EXPORT'}})
    else
      if tbr_target_key == nil and input.operation == "rotate" then
        tbr_target_key = assert(Sobject.create { obj_type = 'AES', key_size = 256, 
            name = "ToBeRotated-"..input.name, key_ops = {'ENCRYPT', 'DECRYPT', 'APPMANAGEABLE', 'EXPORT'}})
      elseif input.operation == "rotate" then
        return { result = tbr_target_key, error = err, message = "rotate BYOK creatTBRkey operation fail"}
      end
    end
    local datestamp = target_key.created_at:sub(1, 8)
  
    -- Create or Get a GCP AES key with skipInitialVersionCreation
    local gcp_key, err = gcp_create_key(input.secret_id, input.location, input.key_ring, input.name, input.labels)
    if gcp_key == nil then
      -- handling create failure
      if input.operation == "create" then 
        target_key:delete()
        return { result = gcp_key, error = err, message = input.operation..": GCP BYOK create key operation failed"}
      end
      -- handling rotate failure
      if tbr_target_key then 
        tbr_target_key:delete() 
        return { result = gcp_key, error = err, message = input.operation..": GCP BYOK rotate key operation failed"}
      end
    end
    local verb = "ENABLED"
    if gcp_key.primary then -- and gcp_key.primary.state == "ENABLED" then 
      -- if cryptoKey.primary exists do not proceed
      verb = "EXISTS"
      if input.operation == "create" then
        local resp = {} 
        resp.message = "Primary cryptoKeyVersion already "..verb.." in GCP for cryptoKey: "..input.name
        return resp
      else
        -- rotate operation, so lets proceed with createKeyVersion and then disable primary cryptoKeyVersion
      end
    end
   
    -- Create or Get a GCP Import Job
    local time = Time.now_insecure()
    local timestamp = time:unix_epoch_seconds() -- '1600453458' -- jobs expire in 3 days, so try and reuse?
    local gcp_import_job, err = gcp_create_import_job(input.secret_id, input.location, input.key_ring, import_job_id..timestamp)
    if gcp_import_job == nil then
      target_key:delete()
      if tbr_target_key then tbr_target_key:delete() end
      gcp_delete_key(input.secret_id, gcp_key)
     return {result = import_params, error = err, message = input.operation..": GCP BYOK import job operation failed"}
    elseif gcp_import_job.state == "PENDING_GENERATION" then
      gcp_import_job, err = gcp_create_import_job(input.secret_id, input.location, input.key_ring, import_job_id..timestamp)
    end

    -- Wrap a local transient key with GCP Import Job's public key
    -- Wrap the target key with the local transient temp key
    local rsaaes_wrapped_key = nil
    if gcp_import_job[1] ~= nil then
      if input.operation == "create" then
        rsaaes_wrapped_key = wrap_keys_for_import(input.secret_id, gcp_import_job[1], target_key)
      else
        rsaaes_wrapped_key = wrap_keys_for_import(input.secret_id, gcp_import_job[1], tbr_target_key)
      end
    else
      return {result = gcp_import_job, error = err, message = input.operation..": GCP BYOK wrap keys operation failed"}
    end
    
    -- Import the wrapped key
    local gcp_key_updated, err = gcp_import_key(input.secret_id, input.location, input.key_ring, input.name,  gcp_key, gcp_import_job[1], rsaaes_wrapped_key)
    if err  ~= nil then
      target_key:delete()
      if tbr_target_key then tbr_target_key:delete() end
      gcp_delete_key(input.secret_id, gcp_key)
      return {result = gcp_key_updated, error = err, message = input.operation..": GCP BYOK import key operation failed"}
    end
    
    -- Disable prior version
    local gcp_key_primary_old
    if gcp_key.primary ~= nil and input.disable_previous then
      gcp_key_primary_old, err = gcp_toggle_key(input.secret_id, input.location, input.key_ring, input.name, gcp_key, 'DISABLED')
    end

    -- Update the master key custom metadata
    if input.operation == "create" then
      target_key:update{custom_metadata = {
          GCP_KEY_ID = gcp_key.name, GCP_KEY_VERSION = gcp_key_updated.primary.name, 
          GCP_CREATED = gcp_key.createTime, GCP_UPDATED = gcp_key_updated.primary.createTime }}
    else
      target_key:update { name = input.name .. '-replaced-by-' .. tbr_target_key.kid }
      tbr_target_key:update{custom_metadata = {
          GCP_KEY_ID = gcp_key.name, GCP_KEY_VERSION = gcp_key_updated.primary.name, 
          GCP_CREATED = gcp_key.createTime, GCP_UPDATED = gcp_key_updated.primary.createTime }}
      tbr_target_key:update { name = input.name }
    end
    return Sobject {name = input.name}

  elseif input.operation == "enable" then
    -- Get a GCP AES key
    local gcp_key, err = gcp_list_keys(input.secret_id, input.location, input.key_ring, input.name)
    if gcp_key == nil then
      return { result = gcp_key, error = err, message = input.operation..": GCP BYOK list keys operation failed"}
    end
    if gcp_key.primary and gcp_key.primary.state == "ENABLED" then
      local resp = {}
      resp.message = "Primary cryptoKeyVersion already ENABLED in GCP for cryptoKey: "..input.name
      return resp
    elseif gcp_key.primary and gcp_key.primary.state == "DISABLED" then
      local gcp_key_primary_old
      if gcp_key.primary ~= nil then
        gcp_key_primary_old, err = gcp_toggle_key(input.secret_id, input.location, input.key_ring, input.name, gcp_key, 'ENABLED')
        local sobj = assert(Sobject {name = input.name})
        assert(sobj:update { enabled = true, 
          custom_metadata = sobj.custom_metadata })
        if gcp_key_primary_old ~= nil then return gcp_key_primary_old end
        return gcp_key_primary_old, err
      end
    elseif gcp_key.primary == nil then
      local resp = {}
      resp.message = "Primary cryptoKeyVersion not set in GCP for cryptoKey: "..input.name
      return resp
    end

  elseif input.operation == "disable" then
    -- Get a GCP AES key 
    local gcp_key, err = gcp_list_keys(input.secret_id, input.location, input.key_ring, input.name)
    if gcp_key == nil then
      return { result = gcp_key, error = err, message = input.operation..": GCP BYOK list keys operation failed"}
    end
    if gcp_key.primary and gcp_key.primary.state == "ENABLED" then
      local gcp_key_primary_old
      if gcp_key.primary ~= nil then
        gcp_key_primary_old, err = gcp_toggle_key(input.secret_id, input.location, input.key_ring, input.name, gcp_key, 'DISABLED')
        local sobj = assert(Sobject {name = input.name})
        assert(sobj:update { enabled = false, 
          custom_metadata = sobj.custom_metadata })
        if gcp_key_primary_old ~= nil then return gcp_key_primary_old end
        return gcp_key_primary_old, err
      end
    elseif gcp_key.primary and gcp_key.primary.state == "DISABLED" then
      local resp = {} 
      resp.message = "Primary cryptoKeyVersion already DISABLED in GCP for cryptoKey: "..input.name
      return resp
    elseif gcp_key.primary == nil then
      local resp = {}
      resp.message = "Primary cryptoKeyVersion not set in GCP for cryptoKey: "..input.name
      return resp
    end

  end -- operation switch
end
