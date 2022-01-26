-- Name: AWS BYOK
-- Version: 2.0
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
-- - Disable AWS BYOK key from Fortanix Self-Defending KMS
-- - Enable AWS BYOK key from Fortanix Self-Defending KMS
-- - Delete AWS BYOK key from Fortanix Self-Defending KMS
-- - Reimport key material from Fortanix Self-Defending KMS to AWS CMK
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
-- ### Disable operation
--
-- This operation will disable a AWS KMS key.
--
-- #### Parameters
--
-- * `operation`: The operation which you want to perform. A valid value is `disable`.
-- * `name`: Name of the key
-- * `secret_id`: The response of `configuration` operation.
--
-- #### Example
--
-- Input JSON
-- ```
-- {
--   "operation": "disable",
--   "name": "test-key",
--   "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
-- }
-- ```
--
-- Output JSON
-- ```
-- {}
-- ```
--
-- ### Enable operation
--
-- This operation will enable a AWS KMS disabled key.
--
-- #### Parameters
--
-- * `operation`: The operation which you want to perform. A valid value is `enable`.
-- * `name`: Name of the key
-- * `secret_id`: The response of `configuration` operation.
--
-- #### Example
--
-- Input JSON
-- ```
-- {
--   "operation": "enable",
--   "name": "test-key",
--   "secret_id": "e84f0b8c-485b-499c-87d5-d583f8716144"
-- }
-- ```
--
-- Output JSON
-- ```
-- {}
-- ```
--
-- ### Release Notes
-- Added support for the following new features:
-- - Disable AWS BYOK key from Fortanix Self-Defending KMS
-- - Enable AWS BYOK key from Fortanix Self-Defending KMS
-- - Schedule deletion for AWS CMK from Fortanix Self-Defending KMS
-- - Reimport key material from Fortanix Self-Defending KMS to AWS CMK

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

disable
{
  "operation": "disable",
  "name": "test-key",
  "secret_id": "d6807129-27fe-4f64-8509-f9d3326c1de5"
}

enable
{
  "operation": "enable",
  "name": "test-key",
  "secret_id": "d6807129-27fe-4f64-8509-f9d3326c1de5"
}

delete
{
  "operation": "delete",
  "name": "test-key",
  "secret_id": "d6807129-27fe-4f64-8509-f9d3326c1de5"
}

reimport
{
  "operation": "reimport",
  "name": "test-key",
  "secret_id": "d6807129-27fe-4f64-8509-f9d3326c1de5"
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

local function plusoneday(strdatetime)
  local dy = 1
  local newdt = strdatetime:gsub(':',''):gsub('%-','')
  local strtm = newdt:sub(-8)
  local odd_mons = {1,1,1,0,1,0,1,1,0,1,0,1}
  local year = tonumber(newdt:sub(0,4))
  local month = tonumber(newdt:sub(5):sub(0,2))
  local date = tonumber(newdt:sub(7):sub(0,2))
  local bump = 'day'
  if odd_mons[month] then
    if month == 2 then
      if date > 27 then
        if year % 4 ~= 0 or (year % 4 == 0 and date == 29) then
          bump = 'mon'
        end
      end
    elseif date == 31 then
      if month == 12 then bump = 'yr'
      else bump = 'mon' end
    end
  elseif date == 30 then bump = 'mon' end
  if bump == 'day' then date = date + 1 end
  if bump == 'mon' then
      date = 1
      month = month + 1
  end
  if bump == 'yr' then
    year = year + 1
    month = 1
    date = 1
  end
  return string.format("%04d%02d%02d%s",year,month,date,strtm)
end

-- ported from https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
function aws_request(secret_id, amzTarget, request_body, method)
  local service = 'kms'
  local region = 'us-east-1'
  local host = service..'.'..region..'.amazonaws.com'
  local endpoint = 'https://'..host

  local sobject, err = assert(Sobject { id = secret_id })
  if sobject.custom_metadata["AccessKey"] == nil then
     err = "AWS credential is not configured or incorrect. Please run cofigure operation."
    return nil, err
  end
  local access_key = assert(sobject.custom_metadata['AccessKey'])
  local secret_key = sobject:export().value:bytes()
  local session_token = ''
  -- read the STS short-lived token, if any obtained from AssumeRole/WithSAML
  local role_arn = sobject.custom_metadata["RoleArn"]
  if role_arn ~= nil and role_arn ~= "" then
    local session_created = sobject.custom_metadata["TokenCreated"]
    if session_created ~= nil then
      last_expiry = tonumber(session_created)
      local time = Time.now_insecure()
      local time_now = time:unix_epoch_seconds()
      -- min is 900s=15m, max is 24h
      if time_now < (session_created + session_ttl ) then
        -- should call assumerole or getsecritytoken again
        session_token = secret_key
        session_token = session_token:sub(41)
        secret_key = secret_key:sub(0, 40)
      end
    else
    end
    if session_token == "" then -- read new token
      return nil, "Invalid session. Renew security token with assumerole."
    end
  end

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
  local headers = { ['X-Amz-Date'] = amzdate, ['X-Amz-Target'] = amzTarget, ['Content-Type'] = content_type, ['Authorization'] = authorization_header}
  if session_token ~= nil and session_token ~= "" then
    -- https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
    headers['X-Amz-Security-Token'] = session_token
  end
  local request_url = endpoint .. '?' .. canonical_querystring

  response, err = request { method = method, url = request_url, headers = headers, body=request_body }
  if response == nil or err ~= nil then
    return nil, err
  end
  if response.status ~= 200 then
    if response.body ~= nil then return json.decode(response.body) end
    return nil, response
  end
  return json.decode(response.body), err
end

function get_sso_token(secret_id)
  local sobject, err = assert(Sobject { id = assert(secret_id) })

  local host = assert(sobject.custom_metadata["AWS_SAML_HOST"])
  if host ~= nil and not string.find(host, "^https://") then host = "https://" .. host end
  local resource = sobject.custom_metadata["AWS_SAML_RESOURCE"]
  local username = assert(sobject.custom_metadata["AWS_SAML_USERNAME"])
  local password = assert(sobject:export().value:bytes())
  local ctype_json = "application/json"
  local headers = { ['Accept'] = ctype_json, ['Content-Type'] = ctype_json }
  local request_url = ""

  local provider = sobject.custom_metadata["AWS_SAML_PROVIDER"]
  if provider == "OKTA" then
  -- https://help.okta.com/en/prod/Content/Topics/DeploymentGuides/AWS/aws-deployment.htm
  -- https://developer.okta.com/docs/guides/session-cookie/overview/#initiate-a-saml-sso-with-the-session-token

    if string.find(host, "/$") then request_url = host .. "api/v1/authn"
    else request_url = host .. "/api/v1/authn" end
    local request_body = { username = username, password = password, options = {multiOptionalFactorEnroll = false, warnBeforePasswordExpired = false} }
    --if true then return { method = method, url = request_url, headers = headers, body=request_body } end
    response, err = request { method = "POST", url = request_url, headers = headers, body=json.encode(request_body) }
    if response and response.status ~= 200 then
      if response ~= nil then return nil, response end
      return nil, err
    else
      if response == nil then return nil, err end
    end
    local sessionToken
    if response.body then
      local auth_resp = json.decode(response.body)
      if auth_resp then sessionToken = auth_resp.sessionToken end
    end
    if sessionToken then
      if string.find(host, "/$") then request_url = host .. "api/v1/sessions"
      else request_url = host .. "/api/v1/sessions" end
      local request_body = { sessionToken = sessionToken }
      --if true then return { method = method, url = request_url, headers = headers, body=request_body } end
      response, err = request { method = "POST", url = request_url, headers = headers, body=json.encode(request_body) }
      if response and response.status ~= 200 then
        if response ~= nil then return nil, response end
        return nil, err
      else
        if response == nil then return nil, err end
      end
      local sessionId
      if response.body then
        local auth_resp = json.decode(response.body)
        if auth_resp then sessionId = auth_resp.id end
      end
      if sessionId then
        if string.find(host, "/$") then request_url = host .. "app/" .. resource .. "/sso/saml"
        else request_url = host .. "/app/" .. resource .. "/sso/saml" end
        local request_body = nil
        headers = { ['Cookie'] = "sid=" .. sessionId } -- IMPORTANT
        --if true then return { method = method, url = request_url, headers = headers, body=request_body } end
        response, err = request { method = "GET", url = request_url, headers = headers, body=json.encode(request_body) }
        if response and response.status ~= 200 then
          if response ~= nil then return nil, response end
          return nil, err
        else
          if response == nil then return nil, err end
        end
        local assertion
        if response.body then
          local saml_resp = response.body:bytes()
          -- extract assertion from saml_resp HTML
          saml_resp = saml_resp:gsub('&#x2b;', '+'):gsub('&#x2f;', '/'):gsub('&#x3d;', '=')
          local sa_start = string.find(saml_resp, 'value="')
          local sa_end = string.find(saml_resp, '"', sa_start+7)
          assertion = string.sub(saml_resp, sa_start+7, sa_end-1)
          --return { resp=saml_resp, sa_start=sa_start, sa_end=sa_end, assertion=assertion }
          local validation1 = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOlJlc3BvbnNlIERlc3RpbmF0aW9u" --<?xml version="1.0" encoding="UTF-8"?><saml2p:Response Destination
          --local validation2 = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c" --<?xml version="1.0" encoding="UTF-8"?>
          if string.find(assertion, validation1) then return assertion end
          return "Hello"

        else return nil, "Failed to perform SSO with " .. sessionId end
      else return nil, "Failed to establish session for " .. sessionToken end
    else return nil, "Failed to authenticate to " .. host end

  else
    return nil, "Unsupported provider"
  end
end

-- https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
-- https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html
function aws_sts_request(secret_id, request_body, method)
  local service = 'sts'
  local region = 'us-east-1'
  local host = service..'.'..'amazonaws.com'
  local endpoint = 'https://'..host
  local access_key
  local sobject, err = Sobject { id = secret_id }
  local proceed = "IAM"
  -- Either neec Access/Secret key or rely on SAML
  if sobject.custom_metadata["AccessKey"] == nil then
    if sobject.custom_metadata["AWS_SAML_PROVIDER"] == nil then proceed = nil
    else
      if sobject.custom_metadata["AWS_SAML_PROVIDER"] == "OKTA" and
        sobject.custom_metadata["AWS_SAML_RESOURCE"] == nil then proceed = nil end
      -- to add more providers
    end
    if sobject.custom_metadata["AWS_SAML_HOST"] == nil then proceed = nil end
    if sobject.custom_metadata["AWS_SAML_USERNAME"] == nil then proceed = nil end
    proceed = "SAML"
  else
    access_key = sobject.custom_metadata['AccessKey']
    if access_key == "" then proceed = nil end
  end
  if proceed == nil or proceed == false then
    err = "AWS or SAML provider credentials are not configured or incorrect. Please run cofigure operation."
    return nil, err
  end

  local content_type = 'application/x-www-form-urlencoded; charset=utf-8' -- couldn't find JSON I/O
  local headers = { ['Content-Type'] = content_type }

  if proceed == "SAML" then
    if not string.find(request_body, "PrincipalArn") then return nil, "Invalid principal role ARN. Try assumerolewithsaml instead." end
    -- construct a SAML authorization for the payload
    local SamlAssertion, err = get_sso_token(secret_id)
    if SamlAssertion == nil then return nil, "Failed to generate SSO token" end

    local assertion_content = Blob.from_base64(SamlAssertion):bytes()
    if not string.find(assertion_content, sobject.custom_metadata.AWS_SAML_USERNAME) then return nil, "Invalid SAML Assertion. Check "..SamlAssertion end
    -- could validate ARNs as well, but need to extract from request_body or accept extra params in function
    local url_encoded_assertion = SamlAssertion:gsub('+', '%%2B'):gsub('/', '%%2F'):gsub('=', '%%3D')

    request_body = request_body:gsub("AssumeRole", "AssumeRoleWithSAML")
    request_body = request_body .. "&SAMLAssertion=" .. url_encoded_assertion
  else
    local amzdate = (Sobject.create { obj_type = 'AES', key_size = 128, transient = true }).created_at
    local datestamp = amzdate:sub(1, 8)
    local secret_key = sobject:export().value:bytes() -- or the password, for SAML
    -- construct a signed header using the canonical payload
    local canonical_uri = '/'
    local canonical_querystring = ''
    local canonical_headers = 'content-type:' .. content_type .. '\n' .. 'host:' .. host .. '\n' .. 'x-amz-date:' .. amzdate .. '\n'
    local signed_headers = 'content-type;host;x-amz-date'

    local payload_hash = assert(digest { data = Blob.from_bytes(request_body), alg = 'SHA256' }).digest:hex():lower()
    local canonical_request = method .. '\n' .. canonical_uri .. '\n' .. canonical_querystring .. '\n' .. canonical_headers .. '\n' .. signed_headers .. '\n' .. payload_hash

  -- FIXME there should be a better way to get the current date/time
    local algorithm = 'AWS4-HMAC-SHA256'
    local credential_scope = datestamp .. '/' .. region .. '/' .. service .. '/' .. 'aws4_request'
    local string_to_sign = algorithm .. '\n' .. amzdate .. '\n' .. credential_scope .. '\n'
          .. digest { alg = 'SHA256', data = Blob.from_bytes(canonical_request) }.digest:hex():lower()

    local signing_key = getSignatureKey(secret_key, datestamp, region, service)
    local signature = sign(signing_key, string_to_sign):hex():lower()

    local authorization_header = algorithm .. ' ' .. 'Credential=' .. access_key .. '/' .. credential_scope
          .. ', ' .. 'SignedHeaders=' .. signed_headers .. ', ' .. 'Signature=' .. signature
    headers = { ['X-Amz-Date'] = amzdate, ['Content-Type'] = content_type, ['Authorization'] = authorization_header}
  end
  local request_url = endpoint .. '/'

  --if true then return { method = method, url = request_url, headers = headers, body=request_body } end
  response = request { method = method, url = request_url, headers = headers, body=request_body }
  return response.body:bytes()
end


function aws_assume_role(secret_id, role_arn, principal_arn)
  local principal_id = principal():id()
  -- c/should check SDKMS principal_id against AWS_SAML_USERNAME, if needed

  local sts_params = "Action=AssumeRole"
  sts_params = sts_params.."&DurationSeconds="..tostring(session_ttl) -- otherwise defaults to 3600
  -- TBD support tags and inline policies as well
  -- sts_params = sts_params.."&PolicyArns.member.2.arn=arn:aws:iam::123456789012:policy/kms-policy"
  -- sts_params = sts_params..'&Policy={"Version":"2012-10-17","Statement":[{"Sid":"KmsStmt","Effect":"Allow","Action":"kms:*","Resource":"*"}]}'
  sts_params = sts_params.."&RoleArn="..assert(role_arn)
  sts_params = sts_params.."&RoleSessionName=ftxplugin-"..principal_id
  sts_params = sts_params.."&Version=2011-06-15"
  if principal_arn then sts_params = sts_params.."&PrincipalArn="..principal_arn end

  local xml_response, err = aws_sts_request(secret_id, sts_params, "POST")
  if xml_response == nil then
    if err ~= nil then return nil, err end
    return nil, "Failed to get STS credentials"
  else

    local str_x, str_y
    str_x = string.find(xml_response, '<AssumedRoleId>') + 15
    str_y = string.find(xml_response, '</AssumedRoleId>') -1
    local session_role_userid = string.sub(xml_response, str_x, str_y)

    str_x = string.find(xml_response, '<AccessKeyId>') + 13
    str_y = string.find(xml_response, '</AccessKeyId>') -1
    local session_access_key = string.sub(xml_response, str_x, str_y)

    str_x = string.find(xml_response, '<SecretAccessKey>') + 17
    str_y = string.find(xml_response, '</SecretAccessKey>') -1
    local session_secret_key = string.sub(xml_response, str_x, str_y)

    str_x = string.find(xml_response, '<SessionToken>') + 14
    str_y = string.find(xml_response, '</SessionToken>') -1
    local session_token = string.sub(xml_response, str_x, str_y)

    str_x = string.find(xml_response, '<Expiration>') + 12
    str_y = string.find(xml_response, '</Expiration>') -1
    local session_expiration = string.sub(xml_response, str_x, str_y)

    str_x = string.find(xml_response, '<RequestId>') + 11
    str_y = string.find(xml_response, '</RequestId>') -1
    session_corrlnid = string.sub(xml_response, str_x, str_y)

  --[[
    if true then
      return {uid=session_role_userid,akey=session_access_key,
      skey=session_secret_key,stok=session_token,
      exp=session_expiration,corr=session_corrlnid}
    end
    ]]--
    local sobject, err = Sobject { name = session_role_id }
    if sobject == nil or err ~= nil then
      sobject = assert(Sobject.import{ name = session_corrlnid, obj_type = "SECRET", value = Blob.from_bytes(session_secret_key..session_token) })
    else
      -- TODO: https://fortanix.atlassian.net/browse/EXTREQ-110
      assert(sobject:update{ name = sobject.name.."-replaced-by-"..session_role_id })
      sobject = assert(Sobject.import{ name = session_corrlnid, obj_type = "SECRET", value = Blob.from_bytes(session_secret_key..session_token) })
    end
    if sobject ~= nil then
      local time = Time.now_insecure()
      local time_now = time:unix_epoch_seconds()
      sobject.custom_metadata = {}
      sobject.custom_metadata["TokenCreated"] = tostring(time_now)
      sobject.custom_metadata["TokenExpiration"] = session_expiration
      sobject.custom_metadata["AccessKey"] = session_access_key
      sobject.custom_metadata["RoleUserId"] = session_role_userid
      sobject.custom_metadata["RoleArn"] = role_arn
      --sobject.custom_metadata["LastRequestId"] = session_corrlnid
      --sobject.custom_metadata["SessionToken"] = session_token
      local session_cleanup = session_expiration
      while clean_after_expire > 0 do
        session_cleanup = plusoneday(session_cleanup)
        clean_after_expire = clean_after_expire - 1
      end
      assert(sobject:update { custom_metadata = sobject.custom_metadata, deactivation_date = session_cleanup })
    end
    return sobject.kid
  end
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

function aws_cancel_key_deletion(secret_id, aws_key_id)
  request_body = '{"KeyId": "' .. aws_key_id .. '"}'
  local cancel_response, err =
      aws_request(secret_id, "TrentService.CancelKeyDeletion", request_body, "POST")
  return cancel_response, err
end

function aws_disable_key(secret_id, aws_key_id)
  request_body = '{"KeyId": "' .. aws_key_id .. '"}'
  local response, err = aws_request(secret_id ,"TrentService.DisableKey", request_body, "POST")
  return response, err
end

function aws_enable_key(secret_id, aws_key_id)
  request_body = '{"KeyId": "' .. aws_key_id .. '"}'
  local response, err = aws_request(secret_id ,"TrentService.EnableKey", request_body, "POST")
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
    local secret = assert(Sobject.import{ name = name, obj_type = "SECRET",
        value = Blob.from_bytes(input.secret_key),
        custom_metadata = { AccessKey = input.access_key }})
    return {secret_id = secret.kid}

  elseif input.operation == "configure_saml" then
    local name = Blob.random { bits = 64 }:hex()
    if input.name then name = input.name end
    local secret = assert(Sobject.import{ name = name, obj_type = "SECRET",
        value = Blob.from_bytes(assert(input.password)),
        custom_metadata = {
          AWS_SAML_PROVIDER = assert(input.provider),
          AWS_SAML_HOST = assert(input.host),
          AWS_SAML_RESOURCE = assert(input.resource),
          AWS_SAML_USERNAME = assert(input.username)
        }})
    return {secret_id = secret.kid}

  elseif input.operation == "assumerole" then
    creds, err = aws_assume_role(input.secret_id, assert(input.role_arn))
    if creds then return creds end
    return err

  elseif input.operation == "assumerolewithsaml" then
    creds = aws_assume_role(input.secret_id, assert(input.role_arn), assert(input.principal_arn))
    if creds then return creds end
    return err

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
  elseif input.operation == "disable" then
    local key = assert(Sobject { name = input.name})
    if key.custom_metadata == nil or key.custom_metadata.AWS_KEY_ID == nil then
      return "the input key ".. input.name .. " is not a valid AWS BYOK Key"
    end
    local resp, err = aws_disable_key(input.secret_id, key.custom_metadata.AWS_KEY_ID)
    if resp == nil then return err end
    return resp
  elseif input.operation == "enable" then
     local key = assert(Sobject { name = input.name})
    if key.custom_metadata == nil or key.custom_metadata.AWS_KEY_ID == nil then
      return "the input key ".. input.name .. " is not a valid AWS BYOK Key"
    end
    local resp, err = aws_enable_key(input.secret_id, key.custom_metadata.AWS_KEY_ID)
    if resp == nil then return err end
    return resp
  elseif input.operation == "delete" then
    local key = assert(Sobject { name = input.name})
    if key.custom_metadata == nil or key.custom_metadata.AWS_KEY_ID == nil then
      return "the input key ".. input.name .. " is not a valid AWS BYOK Key"
    end
    -- key:delete()
    local resp, err = aws_delete_key(input.secret_id, key.custom_metadata.AWS_KEY_ID)
    if resp == nil then return err end
    return resp
  elseif input.operation == "cancel_deletion" then
    local key = assert(Sobject { name = input.name})
    local resp, err = aws_cancel_key_deletion(input.secret_id, key.custom_metadata.AWS_KEY_ID)
    return aws_enable_key(input.secret_id, key.custom_metadata.AWS_KEY_ID)
  elseif input.operation == "reimport" then
    local key = assert(Sobject { name = input.name})
    if key.custom_metadata == nil or key.custom_metadata.AWS_KEY_ID == nil then
      return "the input key ".. input.name .. " is not a valid AWS BYOK Key"
    end
    local aws_key_id = key.custom_metadata.AWS_KEY_ID
    local import_params, err = aws_get_import_params(input.secret_id, aws_key_id)
    if import_params == nil then
      return import_params, err
    end
    local wrapped_key = wrap_key_for_import(input.secret_id, aws_key_id, key, import_params)
    if wrapped_key == nil then
      return "Reimport operation fail"
    end
    local resp, err = aws_import_key(input.secret_id, aws_key_id, wrapped_key, import_params)
    if resp == nil then
      if err and err.body ~= nil then return nil, Blob.from_base64(err.body) end
      return nil, err
    end
    return resp, err
  else
    return nil, "Unsupported operation"
  end
end
