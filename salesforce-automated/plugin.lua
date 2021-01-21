-- Name: Automated BYOK for Salesforce Cloud
-- Version: 1.0
-- Description: ## Short Description
-- This plugin implements the Bring your own key (BYOK) model for Salesforce. Using this plugin you can keep your key inside Fortanix Self-Defending KMS and use Shield Platform Encryption features of Salesforce.
-- ### ## Introduction
-- ## Use cases
-- 
-- The plugin can be used to
-- 
-- - Upload a key from Fortanix Self-Defending KMS to Salesforce
-- - Search tenant secrets (Salesforce encryption keys) using Salesforce Sobject Query Language (SSQL)
-- - Check current status of any key or key version
-- - Destroy the archived keys in Salesforce
-- - Restore a previously destroyed key
-- 
-- ## Fortanix Self-Defending KMS Setup
-- 
-- 1. Log in to Fortanix Self-Defending KMS (https://sdkms.fortanix.com)
-- 2. Create an account in Fortanix Self-Defending KMS
-- 3. Create a group in Fortanix Self-Defending KMS
-- 4. Create a plugin in Fortanix Self-Defending KMS
-- 
-- ## Configure Salesforce
-- 
-- 1. Create a New Profile under Setup >> Profiles.
--     Note: Select “Manage Encryption Keys” under “Administrative Permissions"
-- 2. Create a New User under Setup >> Users with these inputs –
--     Name: arbitrarily input
--     Profiles: choose the KMS role created in previous step
--     Note the credentials to securely import into Self-Defending KMS secret
-- 3. Create a Connected App under “Apps >> App Manager” with the following inputs –
--     Label: arbitrarily input
--     Check the “Enable OAuth Settings”
--     Check the “Enable Device Flow” for automated access
--     Note the credentials to securely import into Self-Defending KMS secret
-- 4. Whitelist the Fortanix Self-Defending KMS application IP range (CIDR)
-- 5. Create a Certificate under “Setup >> Certificate and Key Management” –
--     Label: arbitrarily input, but note it for later use
--     Uncheck the “Exportable Private Key”
--     Check the option to "Use Platform Encryption"
-- 6. Verify the Salesforce credentials
--     Client/Consumer Key  (Created in step 3)
--     Client/Consumer Secret (Created in step 3)
--     OAuth username (Created in step 2)
--     OAuth password (Created in step 2)
--     Tenant URI
--     API version (Fortanix Plugin tested against version 50.0
-- 
-- ## Input/Output JSON object format
-- 
-- ### ### Configure operation
-- 
-- This operation configures Salesforce credentials in Fortanix Self-Defending KMS and returns a UUID. You need to pass this UUID for other operations. This is a one time process.
-- 
-- ### ### parameters
-- 
-- * `operation`: The operation which you want to perform. A valid value is `configure`.
-- * `consumer_key`: Consumer Key of the connected app
-- * `consumer_secret`: Consumer Secret of the connected app
-- * `username`: OAuth username
-- * `password`: OAuth password
-- * `tenant`: Salesforce tenant URI
-- * `version`: API version (Fortanix Plugin tested against version 50.0)
-- * `name`: Name of the sobject. This sobject will be created in fortanix self-Defending KMS and will have Salesforce credential information
-- 
-- ### ### Example
-- 
-- Input JSON
-- ```
-- {
--   "operation": "configure",
--   "consumer_key": "CBK...................D",
--   "consumer_secret": "DMV................D",
--   "username" : "ft......x@<your company domain>",
--   "password" : "fy....K",
--   "tenant"   : "<Salesforce tenant URI>",
--   "version"  : "v50.0",
--   "name"    : "Salesforce NamedCred Dev"
-- }
-- ```
-- Output
-- ```
-- "3968218b-72c3-4ada-922a-8a917323f27d"
-- ```
-- 
-- 
-- ### ### Check operation
-- 
-- This operation is to test whether plugin can import wrapping certificate from salesforce into Fortanix self-Defending KMS. (This certificate is required by plugin to authenticate itself to salesforce)
-- 
-- ### ### parameters
-- 
-- * `operation`: The operation which you want to perform. A valid value is `check`
-- * `secret_id`: The response of `configuration` operation
-- * `wrapper`: Name of the wrapping certificate in salesforce
-- 
-- ### ### Example
-- 
-- Input JSON
-- ```
-- {
--   "operation": "check",
--   "secret_id": "3968218b-72c3-4ada-922a-8a917323f27d",
--   "wrapper"  : "SFBYOK_FTX_Wrapper"
-- }
-- ```
-- Output JSON
-- ```
-- {
--   "group_id": "ff2............................c",
--   "public_only": true,
--   "key_ops": [
--     "VERIFY",
--     "ENCRYPT",
--     "WRAPKEY",
--     "EXPORT"
--   ],
--   "enabled": true,
--   "rsa": {
--     "signature_policy": [
--       {
--         "padding": null
--       }
--     ],
--     "encryption_policy": [
--       {
--         "padding": {
--           "OAEP": {
--             "mgf": null
--           }
--         }
--       }
--     ],
--     "key_size": 4096
--   },
--   "state": "Active",
--   "created_at": "20201229T183553Z",
--   "key_size": 4096,
--   "kid": "6de........................4",
--   "origin": "External",
--   "lastused_at": "19700101T000000Z",
--   "obj_type": "CERTIFICATE",
--   "name": "SFBYOK_FTX_Wrapper",
--   "acct_id": "ec9.......................7",
--   "compliant_with_policies": true,
--   "creator": {
--     "plugin": "654.......................1"
--   },
--   "value": "MII........................9",
--   "activation_date": "20201229T183553Z",
--   "pub_key": "MII......................8",
--   "never_exportable": false
-- }
-- ```
-- 
-- 
-- ### ### Query operation
-- 
-- This operation allows you to search tenant secrets (Salesforce encryption keys) using Salesforce Sobject Query Language (SSQL)
-- 
-- ### ### parameters
-- 
-- * `operation`: The operation which you want to perform. A valid value is `query` or `search`
-- * `secret_id`: The response of `configuration` operation
-- * `query`: SSQL query
-- * `tooling`:
-- * `sandbox`:   To indicate, whether to use test or production tenant.
-- 
-- ### ### Example
-- 
-- Input JSON
-- ```
-- {
--   "operation": "search",
--   "secret_id": "3968218b-72c3-4ada-922a-8a917323f27d",
--   "query"   : "select Id, Status, Version from TenantSecret where Type = `Data`",
--   "tooling"  : false,
--   "sandbox"  : false
-- }
-- ```
-- Output JSON
-- ```
-- {
--   "done": true,
--   "totalSize": 5,
--   "records": [
--     {
--       "attributes": {
--         "type": "TenantSecret",
--         "url": "/services/data/v50.0/sobjects/TenantSecret/02G..........O"
--       },
--       "Status": "ARCHIVED",
--       "Id": "02G.............D",
--       "Version": 3
--     },
--     {
--       "Version": 1,
--       "attributes": {
--         "url": "/services/data/v50.0/sobjects/TenantSecret/02G...........W",
--         "type": "TenantSecret"
--       },
--       "Id": "02G...........W",
--       "Status": "ARCHIVED"
--     },
--     {
--       "Version": 2,
--       "Id": "02G..........O",
--       "attributes": {
--         "type": "TenantSecret",
--         "url": "/services/data/v50.0/sobjects/TenantSecret/02G............O"
--       },
--       "Status": "ARCHIVED"
--     },
--     {
--       "Id": "02G...........4",
--       "attributes": {
--         "url": "/services/data/v50.0/sobjects/TenantSecret/02G...........4",
--         "type": "TenantSecret"
--       },
--       "Version": 4,
--       "Status": "DESTROYED"
--     },
--     {
--       "attributes": {
--         "type": "TenantSecret",
--         "url": "/services/data/v50.0/sobjects/TenantSecret/02G............O"
--       },
--       "Id": "02G..........O",
--       "Version": 5,
--       "Status": "ACTIVE"
--     }
--   ]
-- }
-- ```
-- 
-- ### ### Upload operation
-- 
-- This operation allows you to create a key material in Fortanix self-Defending KMS and upload to salesforce
-- 
-- ### ### parameters
-- 
-- * `operation`: The operation which you want to perform. A valid value is `upload`.
-- * `secret_id`: The response of `configuration` operation
-- * `wrapper`: Name of the wrapping certificate in salesforce
-- * `type`: A valid values are `Data|EventBus|SearchIndex`
-- * `mode`: Key derivation mode. It can be blank which defaults to “PBKDF2” or can also be "NONE" to disable key derivation in Salesforce.
-- * `name`: Prefix of the name
-- * `sandbox`:  To indicate, whether to use test or production tenant.
-- 
-- ### ### Example
-- 
-- Input JSON
-- ```
-- {
--   "operation": "upload",
--   "secret_id": "3968218b-72c3-4ada-922a-8a917323f27d",
--   "wrapper"  : "SFBYOK_FTX_Wrapper",
--   "type"     : "Data",
--   "mode"     :  "",
--   "name"     : "Salesforce Data Key",
--   "sandbox"  : false
-- }
-- 
-- ```
-- Output JSON
-- ```
-- {
--   "obj_type": "AES",
--   "custom_metadata": {
--     "SF_HASH": "ESP.......................=",
--     "SF_UPLOAD": "EDF.....................=",
--     "SF_WRAPPER": "SFBYOK_FTX_Wrapper",
--     "SF_MODE": "",
--     "SF_KID": "02G...........O",
--     "SF_TYPE": "Data"
--   },
--   "acct_id": "ec9...................7",
--   "creator": {
--     "plugin": "654....................1"
--   },
--   "public_only": false,
--   "origin": "Transient",
--   "kid": "bb7................3",
--   "lastused_at": "19700101T000000Z",
--   "activation_date": "20201229T185549Z",
--   "key_size": 256,
--   "kcv": "b5...9",
--   "name": "Salesforce Data Key 20201229T185546Z",
--   "state": "Active",
--   "enabled": true,
--   "key_ops": [
--     "EXPORT"
--   ],
--   "compliant_with_policies": true,
--   "created_at": "20201229T185549Z",
--   "aes": {
--     "tag_length": null,
--     "key_sizes": null,
--     "random_iv": null,
--     "fpe": null,
--     "iv_length": null,
--     "cipher_mode": null
--   },
--   "never_exportable": false,
--   "group_id": "ff2..............b"
-- }
-- ```
-- 
-- ### ### Status operation
-- 
-- This operation allows you to obtain current status of a salesforce key
-- 
-- ### ### parameters
-- 
-- * `operation`: The operation which you want to perform. A valid value is `status`.
-- * `secret_id`: The response of `configuration` operation
-- * `wrapper`: Name of the wrapping certificate in salesforce
-- * `name`: "name of corresponding sobject in fotanix self-Defending KMS"
-- * `sandbox`:   To indicate, whether to use test or production tenant.
-- 
-- ### ### Example
-- 
-- Input JSON
-- ```
-- {
--       "operation" : "status",
--       "secret_id": "3968218b-72c3-4ada-922a-8a917323f27d",
--       "wrapper"   : "SFBYOK_FTX_Wrapper",
--       "name"      : "Salesforce Data Key 20201229T185546Z",
--       "sandbox"   : false
-- }
-- ```
-- Output JSON
-- ```
-- {
--   "RemoteKeyIdentifier": null,
--   "CreatedDate": "2020-12-29T18:55:49.000+0000",
--   "SecretValueHash": "ESP........................=",
--   "CreatedById": "005..........2",
--   "KeyDerivationMode": "PBKDF2",
--   "attributes": {
--     "url": "/services/data/v50.0/sobjects/TenantSecret/02G..........O",
--     "type": "TenantSecret"
--   },
--   "LastModifiedDate": "2020-12-29T18:55:49.000+0000",
--   "IsDeleted": false,
--   "SecretValue": "CgM.............................=",
--   "SecretValueCertificate": null,
--   "Type": "Data",
--   "RemoteKeyServiceId": null,
--   "Version": 6,
--   "Id": "02G..........O",
--   "Status": "ACTIVE",
--   "SystemModstamp": "2020-12-29T18:55:49.000+0000",
--   "RemoteKeyCertificate": null,
--   "Source": "UPLOADED",
--   "Description": "Salesforce Data Key 20201229T185546Z",
--   "LastModifiedById": "005............2"
-- }
-- ```
-- ### ### Sync operation
-- 
-- This operation allows you to sync Fortanix self-Defending key object with salesforce key.
-- 
-- ### ### parameters
-- 
-- * `operation`: The operation which you want to perform. A valid value is `sync`.
-- * `secret_id`: The response of `configuration` operation
-- * `wrapper`: Name of the wrapping certificate in salesforce
-- * `name`: "name of corresponding sobject in fotanix self-Defending KMS"
-- * `sandbox`:   To indicate, whether to use test or production tenant.
-- 
-- ### ### Example
-- 
-- Input JSON
-- ```
-- {
--       "operation" : "sync",
--       "secret_id": "3968218b-72c3-4ada-922a-8a917323f27d",
--       "wrapper"   : "SFBYOK_FTX_Wrapper",
--       "name"      : "Salesforce Data Key 20201229T185546Z",
--       "sandbox"   : false
-- }
-- ```
-- Output JSON
-- ```
-- {
--   "RemoteKeyCertificate": null,
--   "IsDeleted": false,
--   "CreatedById": "005..............2",
--   "Status": "ACTIVE",
--   "Type": "Data",
--   "LastModifiedById": "005............2",
--   "CreatedDate": "2020-12-29T18:55:49.000+0000",
--   "SystemModstamp": "2020-12-29T18:55:49.000+0000",
--   "Source": "UPLOADED",
--   "SecretValueHash": "ESP.................c",
--   "LastModifiedDate": "2020-12-29T18:55:49.000+0000",
--   "Version": 6,
--   "RemoteKeyServiceId": null,
--   "RemoteKeyIdentifier": null,
--   "attributes": {
--     "type": "TenantSecret",
--     "url": "/services/data/v50.0/sobjects/TenantSecret/02G............O"
--   },
--   "KeyDerivationMode": "PBKDF2",
--   "Id": "02G...........O",
--   "SecretValueCertificate": null,
--   "Description": "Salesforce Data Key 20201229T185546Z",
--   "SecretValue": "CgM........................M"
-- }
-- ```
-- ### ### Destroy operation
-- 
-- This operation allows you to destroy an archived salesforce key.
-- 
-- ### ### parameters
-- 
-- * `operation`: The operation which you want to perform. A valid value is `destroy`.
-- * `secret_id`: The response of `configuration` operation
-- * `wrapper`: Name of the wrapping certificate in salesforce
-- * `name`: "name of corresponding sobject in fotanix self-Defending KMS"
-- * `sandbox`:   To indicate, whether to use test or production tenant.
-- 
-- ### ### Example
-- 
-- Input JSON
-- ```
-- {
--       "operation" : "destroy",
--       "secret_id": "3968218b-72c3-4ada-922a-8a917323f27d",
--       "wrapper"   : "SFBYOK_FTX_Wrapper",
--       "name"      : "Salesforce Data Key 20201229T185546Z",
--       "sandbox"   : false
-- }
-- ```
-- Output
-- ```
-- output is empty, with http status indicating success.
-- ```
-- ### ### Restore operation
-- 
-- This operation allows you to restore a destroyed salesforce key.
-- 
-- ### ### parameters
-- 
-- * `operation`: The operation which you want to perform. A valid value is `restore`.
-- * `secret_id`: The response of `configuration` operation
-- * `wrapper`: Name of the wrapping certificate in salesforce
-- * `name`: "name of corresponding sobject in fotanix self-Defending KMS"
-- * `sandbox`:   To indicate, whether to use test or production tenant.
-- 
-- ### ### Example
-- 
-- Input JSON
-- ```
-- {
--       "operation" : "restore",
--       "secret_id": "3968218b-72c3-4ada-922a-8a917323f27d",
--       "wrapper"   : "SFBYOK_FTX_Wrapper",
--       "name"      : "Salesforce Data Key 20201229T185546Z",
--       "sandbox"   : false
-- }
-- ```
-- Output
-- ```
-- output is empty, with http status indicating success.
-- ``` 
-- 
-- ### Release Notes
-- - Initial release

--[[
{
  "operation": "configure",
  "consumer_key": "3MV....................................M",
  "consumer_secret": "D16..............................B",
  "username" : "ftx....k@<your company domain>",
  "password" : "tes....K",
  "tenant"   : <salesforce tenant uri>,
  "version"  : "v50.0",
  "name"    : "Salesforce NamedCred Dev"
}
{
  "operation": "check",
  "secret_id": "66ace024-f175-4e0d-bb41-655faae3d475",
  "wrapper"  : "SFBYOK_FTX_Wrapper"
}
{
  "operation" : "select",
  "secret_id" : "66ace024-f175-4e0d-bb41-655faae3d475",
  "sobject"  : "TenantSecret",
  "tooling"   : false,
  "method"    : "GET|PUT|PATCH|DELETE",
  "body"     : { "Name":"FTX_BYOK_Updated" },
  "sandbox"   : false
}
{
  "operation": "search",
  "secret_id": "66ace024-f175-4e0d-bb41-655faae3d475",
  "query"   : "select MasterLabel from Certificate where DeveloperName = 'SFBYOK_FTX_Wrapper'",
  "tooling"  : true,
  "sandbox"  : false
}
{
  "operation": "upload",
  "secret_id": "66ace024-f175-4e0d-bb41-655faae3d475",
  "wrapper"  : "Fortanix BYOK Certificate",
  "type"     : "Data|SearchIndex|EventBus",
  "mode"     :  "",
  "name"     : "Salesforce Data Key",
  "sandbox"  : false
}
{
  "operation" : "status|sync|archive|destroy|restore",
  "secret_id" : "66ace024-f175-4e0d-bb41-655faae3d475",
  "wrapper"   : "SFBYOK_FTX_Wrapper",
  "name"      : "Salesforce Key 20201023T180906Z",
  "sandbox"   : false
}
]]--

local DEBUG = "REQ0"
local sf_secret
local content_type_js  = 'application/json'
local content_type_url = 'application/x-www-form-urlencoded; charset=utf-8'
local sf_services = '/services/data/'
local sf_version  = 'v50.0'
local sf_tooling  = '/tooling'
local sf_metadata  = '/metadata'
local sf_resource = '/sobjects'
local sf_search = '/query'
local sf_object = "TenantSecret"
local sf_login_url = "https://login.salesforce.com/services/oauth2/token"

-- Internal helpers
function get_auth_token()
  assert(sf_secret.consumer_key)
  assert(sf_secret.login_url)
  
  local headers = { ['Content-Type'] = content_type_url }
    local request_body = "grant_type=password&client_id="..sf_secret.consumer_key..
      "&client_secret="..sf_secret.consumer_secret..
      "&username="..sf_secret.username..
      "&password="..sf_secret.password

  local req_obj = { method="POST", url=sf_secret.login_url, headers=headers, body=request_body }
  if DEBUG == "AUTH1" then return req_obj end
  local response, err = request (req_obj)
  if DEBUG == "AUTH2" then return {rsp=response, err=err} end
  if response.status ~= 200 then return nil, response end
  
  local token_obj = json.decode(response.body)
  sf_secret.tenant = token_obj.instance_url
  sf_secret.token = token_obj.access_token
  sf_secret.issued = token_obj.issued_at
  return token_obj.token_type
end

function sf_request(target, request_body, method, response_key)
  local resp = get_auth_token()
  if string.find(DEBUG, "^AUTH%d$") then return resp end
  if "Bearer" ~= resp then return nil, "Missing token" end
  assert(sf_secret.token)
  
  local auth_bearer = "Bearer "..sf_secret.token
  local headers = { ['Content-Type'] = content_type_js, ['Authorization'] = auth_bearer }
  
  if string.sub(target, 1, 1) ~= "/" then target = "/"..target end
  local req_url = sf_secret.tenant .. target
  if type(request_body) == "table" then
    request_body = json.encode(request_body)
  end
  local req_obj = { method=method, url=req_url, headers=headers, body=request_body }
  if DEBUG == "REQ1" then return req_obj end
  local response, err = request (req_obj)
  if DEBUG == "REQ2" then return {rsp=response, err=err} end
  if response.status ~= 200 and response.status ~= 201 and response.status ~= 204 then 
    if response.body ~= nil then return nil, json.decode(response.body) end
    return nil, response
  end
  
  local res_obj
  if response.body ~= nil and response.body ~= "" then
    res_obj = json.decode(response.body)
  end
  if response_key ~= nil and type(response_key) == "string" then
    if res_obj[response_key] ~= nil then return res_obj[response_key] end
  end
  if res_obj ~= nil then return res_obj end
  if response.body ~= nil then return response.body end
  if response ~= nil then return response end
  return nil, err
end

-- Plugin methods
function configure(input)
  if type(input.tenant) ~= "string" then
    return nil, "Need a valid tenant, API version defaults to " .. sf_version
  elseif type(input.consumer_key) ~= "string" then
    return nil, "Need a valid consumer_key"
  elseif type(input.consumer_secret) ~= "string" then
    return nil, "Need a valid consumer_secret"
  elseif type(input.username) ~= "string" then
    return nil, "Need a valid username"
  elseif type(input.password) ~= "string" then
    return nil, "Need a valid password"
  else
    if input.version ~= nil and type(input.version) == "string" then
      if string.find(input.version, "^v?%d%d%.%d$") then
        sf_version = input.version
        if "v" ~= string.sub(sf_version, 1, 1) then sf_version = "v" .. sf_version end
      end
    end
    local name = Blob.random { bits = 64 }:hex()
    if input.name ~= nil then name = input.name end
    local secret_zero = assert(Sobject.import { obj_type = 'SECRET',
      name = name, value = Blob.from_bytes(json.encode(input)),
      custom_metadata = { 
          ["Tenant"] = input.tenant, 
          ["Version"] = sf_version }
      })
    return secret_zero.kid
  end
end

function run_query(input)
  assert(sf_secret)
  if input.query == nil or input.query == "" then return nil, "Invalid search query"
  else sf_object = input.query end
  local api_type = ""
  if input.tooling then api_type = sf_tooling end
  if input.metadata then api_type = sf_metadata end
  
  local target = sf_services .. sf_version .. api_type .. sf_search .. "/?q=" .. sf_object
  local resp, err = sf_request(target, "", "GET", input.lookup)
  if resp == nil then return err end
  return resp
end

function select_sobject(input)
  assert(sf_secret)
  local api_type = ""
  if input.tooling then api_type = sf_tooling end
  if input.metadata then api_type = sf_metadata end
  if input.sobject ~= nil then sf_object=input.sobject end
  local body = ""
  if input.body ~= nil then 
    if type(input.body) == "string" then body=input.body end
    if type(input.body) == "table" then body=json.encode(input.body) end
  end
  local method = "GET"
  if input.update then method="POST" end
  if input.method == "POST" or input.method == "PATCH" or input.method == "DELETE" then 
    method=input.method
  end

  local target = sf_services .. sf_version .. api_type .. sf_resource .. "/" .. sf_object
  local resp, err = sf_request(target, body, method, input.lookup)
  if resp == nil then return err end
  return resp
end

function get_byok_cert(sf_cert_label)
  -- Label to Id lookup
  assert(sf_cert_label)
  local sf_cert_sobj = Sobject{name = sf_cert_label}
  if sf_cert_sobj ~= nil then return sf_cert_sobj end
  
  local params =  { tooling = true, lookup = "records", 
  query = "select Id from Certificate where MasterLabel = '" .. sf_cert_label .. "'" }
  
  local resp = run_query(params)
  if resp ~= nil and resp[1] ~= nil then
    local sf_cert_id = resp[1].Id
    if sf_cert_id == nil or sf_cert_id == "" then return nil, "Failed cert lookup" end
    
    params["sobject"] =  "Certificate/" .. sf_cert_id .. "/CertificateChain"
    params["lookup"] =  nil
    local cert_value = select_sobject(params)
    local sf_cert_sobj = assert(Sobject.import { name = sf_cert_label, transient = false, 
      obj_type = "CERTIFICATE", value = cert_value, key_ops = {'WRAPKEY', 'ENCRYPT', 'VERIFY', 'EXPORT'} })
    return sf_cert_sobj
  end
end

function upload_byok(input)
  local sf_cert_label = "SFBYOK_FTX_Wrapper"
  if input.wrapper ~= nil then sf_cert_label = input.wrapper end
  local tmp_sf_cert_sojbj = get_byok_cert(sf_cert_label)
  if tmp_sf_cert_sojbj == nil then return nil, "Failed wrapper lookup" end
  if tmp_sf_cert_sojbj.custom_metadata ~= nil and tmp_sf_cert_sojbj.custom_metadata["Name"] ~= nil then
    if tmp_sf_cert_sojbj.custom_metadata["Name"] ~= "" then
      sf_cert_label = tmp_sf_cert_sojbj.custom_metadata.Name
    end
  end

  local sf_byok_desc = "SFBYOK_FTX_SecretKey"
  if input.name ~= nil then sf_byok_desc = input.name end
  
  local tmp_sf_byok_sobj
  if input.operation == "upload" then 
    tmp_sf_byok_sobj = assert(Sobject.create { name = sf_byok_desc, transient = true, 
      obj_type = 'AES', key_size = 256, key_ops = {'EXPORT'}})
    sf_byok_desc = sf_byok_desc.." "..tmp_sf_byok_sobj.created_at
  else -- restore
    tmp_sf_byok_sobj = assert(Sobject{ name = assert(input.name) })
  end
  
  local tmp_sf_byok_enc = assert(tmp_sf_cert_sojbj:wrap {
      subject = tmp_sf_byok_sobj, alg = 'RSA', mode = 'OAEP_MGF1_SHA1'})
  
  local tmp_sf_byok_sha256 = assert(digest { alg = 'SHA256', 
      data = tmp_sf_byok_sobj:export().value }).digest
  
  local sf_byok_type = "Data"
  if input.type ~= nil then sf_byok_type = input.type end
  if sf_byok_type ~= "" and sf_byok_type ~= "Data" and 
    sf_byok_type ~= "SearchIndex" and sf_byok_type ~= "DeterministicData" and 
    sf_byok_type ~= "EventBus" and sf_byok_type ~= "Analytics" and 
    sf_byok_type ~= "SalesforceDatabase" then
    sf_byok_type = "Data" -- default
  end
  local sf_byok_mode = ""
  if input.mode ~= nil then sf_byok_mode = input.mode end
  if sf_byok_mode ~= "" and sf_byok_mode ~= "PBKDF2" and sf_byok_mode ~= "NONE" then
    sf_byok_mode = "" -- default
  end

  local sf_key_payload = { SecretValueCertificate = sf_cert_label, 
    SecretValue = tmp_sf_byok_enc.wrapped_key, SecretValueHash = tmp_sf_byok_sha256, 
    description = sf_byok_desc, type = sf_byok_type, KeyDerivationMode = sf_byok_mode }
  if DEBUG == "BYOK1" then return sf_key_payload end
  if input.operation ~= "upload" then -- restore
    return sf_key_payload
  end
  
  sf_object = "TenantSecret"
  local target = sf_services .. sf_version .. sf_resource .. "/" .. sf_object
  local sf_secret_obj, err = sf_request(target, sf_key_payload, "POST")
  if sf_secret_obj == nil then return err end
  if DEBUG == "REQ2" and sf_secret_obj.rsp ~= nil and sf_secret_obj.rsp.body ~= nil then
    sf_secret_obj = json.decode(sf_secret_obj.rsp.body)
  end
  if DEBUG == "BYOK2" then return sf_secret_obj end
  local sf_kid = ""
  local sf_metadata
  if sf_secret_obj ~= nil and sf_secret_obj.id ~= nil then
    sf_kid = sf_secret_obj.id
    sf_metadata = { SF_KID = sf_kid, SF_TYPE = sf_byok_type, SF_MODE = sf_byok_mode, 
      SF_WRAPPER = sf_cert_label, SF_UPLOAD = sf_key_payload.SecretValue:base64(), SF_HASH = sf_key_payload.SecretValueHash:base64() }
  end

  local persisted_byok = assert(tmp_sf_byok_sobj:persist{ name = sf_byok_desc, custom_metadata = {SF_KID = sf_kid} })
  if DEBUG == "BYOK3" then return sf_metadata end
  if DEBUG == "BYOK4" then return persisted_byok end

  -- need to refetch as persisted sobject doesn't handle :update
  tmp_sf_byok_sobj = assert(Sobject{ name = assert(sf_byok_desc) })
  assert(tmp_sf_byok_sobj:update{ custom_metadata = sf_metadata })
  return tmp_sf_byok_sobj
end

function change_status(input)
  local key_label = assert(input.name)
  local new_status = assert(input.operation)
  local sf_sobj = assert(Sobject{name = assert(key_label)})
  local sf_byok_id
  if sf_sobj.custom_metadata and sf_sobj.custom_metadata["SF_KID"] then
    sf_byok_id = sf_sobj.custom_metadata.SF_KID
  end
  
  input.sobject = "TenantSecret/" .. sf_byok_id
  input.method  = "PATCH"

  if input.operation == "archive" then
    input.body    = { Status = "Archived" }
    -- retains the SecretValue but simply patches Status

  elseif input.operation == "destroy" then
    -- destroys the SecretValue but retains the SecretValueHash
    -- can only be restored with original SecretValue
    -- failing restore with existing key wrapped again with cert -- see line 301
    if sf_sobj.custom_metadata.SF_UPLOAD and sf_sobj.custom_metadata.SF_UPLOAD ~= "" then
      input.body    = { Status = "Destroyed" }
    else
      if input.force == nil or input.force == false then
        return nil, "Sync key before destroy or use force"
      end
    end
    
  elseif input.operation == "restore" then
    -- reimport original SecretValue, unable to rewrap with same cert??
    -- Salesforce validates SecretValueHash upon PATCH
    -- backup SecretValue for restore later
    input.sf_kid = sf_byok_id
    local sf_byok_export
    if sf_sobj.custom_metadata and sf_sobj.custom_metadata["SF_UPLOAD"] then
      sf_byok_export = sf_sobj.custom_metadata.SF_UPLOAD -- :export().value
    else
      return nil, "Missing wrapped key backup, should sync next time"
      -- can wrap again, but SF rejects the new payload with Invalid Secret/Key
      -- sf_byok_export = upload_byok(input)
    end
    if string.find(DEBUG, "^BYOK%d$") then return sf_byok_export end
    input.body = { Status = "Archived", SecretValue = sf_byok_export }

  else
    -- operation == "status"
    input.method  = "GET"
  end

  local operation_resp = select_sobject(input) -- perform the op

  if input.operation == "sync" then
    local sf_metadata = sf_sobj.custom_metadata
    sf_metadata.SF_KID = operation_resp.Id
    sf_metadata.SF_TYPE = operation_resp.Type
    sf_metadata.SF_MODE = operation_resp.KeyDerivationMode
    sf_metadata.SF_HASH = operation_resp.SecretValueHash
    sf_metadata.SF_UPLOAD = operation_resp.SecretValue
    sf_metadata.SF_VERSION = tostring(operation_resp.Version)
    assert(sf_sobj:update{ custom_metadata = sf_metadata })
  end
  return operation_resp
end

-- Standard functions
function check(input)
  if input.DEBUG ~= nil then DEBUG = input.DEBUG end
  if input.debug ~= nil then DEBUG = input.debug end

  if input.operation == nil then
    return nil, "Need a valid operation"
  elseif input.operation ~= "configure" then
    if input.secret_id == nil or type(input.secret_id) ~= "string" then
      return nil, "Need a valid secret_id"
    else
      local sf_sec_raw = Sobject{ kid = input.secret_id}
      if sf_sec_raw == nil then
        return nil, "Need a valid secret_id"
      else
        local sf_sec_raw_blob = sf_sec_raw:export().value:bytes()
        sf_secret = json.decode(sf_sec_raw_blob)
        if input.sandbox then sf_login_url = sf_login_url:gsub('login','test') end
        sf_secret.login_url = sf_login_url
        sf_secret.tenant  = sf_sec_raw.custom_metadata["Tenant"]
        sf_secret.version = sf_sec_raw.custom_metadata["Version"]
      end
    end
  end
end
  
function run(input, url, method)
  if input.operation == "configure" then
    return configure(input)
  elseif input.operation == "check" then
    return get_byok_cert(assert(input.wrapper))
  elseif input.operation == "select" then
    return select_sobject(input)
  elseif input.operation == "search" or input.operation == "query" then
    return run_query(input)
  elseif input.operation == "upload" or input.operation == "test" then
    return upload_byok(input)
  elseif input.operation == "status" or input.operation == "sync" or 
    input.operation == "archive" or input.operation == "destroy" or 
    input.operation == "restore" then
    return change_status(input)
  else
    return nil, "Invalid operation"
  end
end

