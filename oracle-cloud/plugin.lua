local vault_prefix = nil
local service = 'kms'
local host = 'oraclecloud.com'
local api_version = '/20180608'
local content_type = 'application/json'
local default_region = 'us-ashburn-1'

local function mon(mn)
  local months = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"}
  return months[mn]
end

local function dayofweek(ts, fmt)
  local indx = (math.floor(ts/86400)+4)%7
  local days = {"Mon","Tue","Wed","Thu","Fri","Sat","Sun"}
  if fmt == true then return days[indx] else return indx end
end

local function replace(str, what, with)
    what = string.gsub(what, "[%(%)%.%+%-%*%?%[%]%^%$%%]", "%%%1") -- escape pattern
    with = string.gsub(with, "[%%]", "%%%%") -- escape replacement
    return string.gsub(str, what, with)
end

local function percent_encode_char(c)
  return string.format("%%%02X", c:byte())
end

local function url_encode(str)
  local r = str:gsub("[^a-zA-Z0-9.~_-%=?&/]", percent_encode_char)
  return r
end

local function to_rfc3339(ts)
  return ts:sub(0,4).."-"..ts:sub(5,6).."-"..ts:sub(7,8)..
    "T"..ts:sub(10,11)..":"..ts:sub(12,13)..":"..ts:sub(14,15).."+00:00" 
end

function oci_request(secret_id, region, api_target, request_body, method)
  local cred_err = "OCI credential is not configured or incorrect. Please run cofigure operation."
  local sobject, err = Sobject { id = secret_id }
  if sobject == nil or
    sobject.custom_metadata == nil or
    sobject.custom_metadata["TenantOCID"] == nil or
    sobject.custom_metadata["UserOCID"] == nil then
    return nil, cred_err
  end
  if err ~= nil then return nil, err end
  
  if vault_prefix == nil then vault_prefix = sobject.custom_metadata['VaultPrefix'] end
  local region = assert(sobject.custom_metadata['Region'])
  if service == nil or service == '' then service = assert(sobject.custom_metadata['Service']) end
  local oci_host = service..'.'..region.."."..host
  if vault_prefix ~= '' and vault_prefix ~= nil then
    oci_host = vault_prefix ..'.'.. oci_host
  end
  local endpoint = 'https://'..oci_host
  
  local md5 = assert(sobject.custom_metadata['MD5'])
  local tenant = assert(sobject.custom_metadata['TenantOCID'])
  local user = assert(sobject.custom_metadata['UserOCID'])

  local today = assert(Time.now_insecure())
  local today_s = today:to_iso8601()
  local oci_date = dayofweek(today:unix_epoch_seconds(), true) .. ", " ..
    today_s:sub(7,8) .. " " .. mon(tonumber(today_s:sub(5,6))) .. " " ..
    today_s:sub(0,4) .. " " .. 
    today_s:sub(10,11) ..":".. today_s:sub(12,13) ..":".. today_s:sub(14,15) .." GMT"
  
  local req_target = method:lower() .." ".. url_encode(api_target)

  local signed_headers = 'date (request-target) host'
  local signing_string = "date: "..oci_date.."\n".."(request-target): "..
    req_target.."\n".."host: "..oci_host
  
  local sha256_hash = assert(digest{data=Blob.from_bytes(request_body),alg='SHA256'}).digest
  if method:lower() == "post" then
    signed_headers = signed_headers .. " x-content-sha256 content-type content-length"
    signing_string = signing_string .. "\nx-content-sha256: " ..sha256_hash:base64() .. 
      "\ncontent-type: "..content_type.."\ncontent-length: "..
      string.len(request_body)
  end

  local algorithm = 'RSA-SHA256'
  local authzn_header = 'Signature version="1",'..
    'headers="'..signed_headers..'",'..
    'keyId="'..tenant..'/'..user..'/'..md5..'",'..
    'algorithm="'..algorithm:lower()..'",'..
    'signature="'..sobject:sign{hash_alg="SHA256",
      data=Blob.from_bytes(signing_string),mode=PKCS1_V15}.signature:base64()..'"'

  local headers = { date=oci_date,host=oci_host,
    ["content-type"]=content_type,authorization=authzn_header}
  
  if method:lower() == "post" then
    headers["x-content-sha256"] = sha256_hash:base64()
  end

  local request_url = endpoint .. url_encode(api_target)
  local call_params = { method = method, url = request_url, headers = headers, body=request_body }
  --if true then return call_params end

  response, err = request(call_params)
  if err ~= nil then 
    call_params.err = err
    call_params.signed = signing_string
    return call_params
  end
  if response.status ~= 200 then
    if response.body then
      call_params.err = json.decode(response.body)
      call_params.signed = signing_string
      return call_params
    end
    return nil, "Unknown error"
  end
  return json.decode(response.body), err
end

-----------------------------------------------------------------------------------

function configure_secret(secret_key, fingerprint, ocid_tenant, ocid_user, region, ocid_comptmt, vault_endpoint)
  local sobj, err
  local name = ""
  if type(secret_key) == "string" then
    sobj, err = Sobject { name = secret_key }
    if sobj == nil then 
      sobj = Sobject { kid = secret_key }
    end
    if vault_endpoint ~= nil and vault_endpoint ~= "" then
      vault_prefix = vault_endpoint.."-management"
    end

    local ocid_attribs = {
      ["MD5"] = fingerprint, 
      ["Region"] = region, 
      ["TenantOCID"] = ocid_tenant, 
      ["UserOCID"] = ocid_user,
      ["CompartmentOCID"] = ocid_comptmt,
      ["VaultPrefix"] = vault_prefix
    }

    if sobj == nil then
      -- new private key with meta to import into a secret
      local pkey = secret_key
      if string.sub(secret_key, 6, 22) == "BEGIN PRIVATE KEY" or
        string.sub(secret_key, 6, 26) == "BEGIN RSA PRIVATE KEY" then
        pkey = secret_key:gsub('\n', '')
        pkey = pkey:gsub('-', '')
        pkey = pkey:gsub('BEGIN PRIVATE KEY', '')
        pkey = pkey:gsub('BEGIN RSA PRIVATE KEY', '')
        pkey = pkey:gsub('END PRIVATE KEY', '')
        pkey = pkey:gsub('END RSA PRIVATE KEY', '')
      end
      sobj = assert(Sobject.import{ obj_type = "RSA", 
          name = Blob.random { bits = 64 }:hex(),
          value = Blob.from_base64(pkey),
          custom_metadata = ocid_attribs
        })
    else
      if sobj.obj_type ~= "RSA" or 
        sobj.public_only == true or sobj.state == "Deactivated" then
        return nil, "Invalid secret key, try again."
      end
      assert(sobj:update { custom_metadata = ocid_attribs })
    end
  end
  if sobj == nil then
    return {result = secret_key, error = err, message = "Configure BYOK needs a secret private key"}
  end
  return sobj
end

--###############################################################################--

function oci_op(secret_id, body, region, method, compartment, resource, vault_endpoint, protection, algo)
  local target = api_version .. "/" .. resource
  local filter = ""
  if body == nil or body == "" then
    if compartment == nil or compartment == "" then
      compartment = assert(Sobject{id=secret_id}).custom_metadata['CompartmentOCID']
    end
    if compartment ~= nil and compartment ~= "" then
      if filter == "" then filter = "?" else filter = filter.."&" end
      filter = filter .."compartmentId=".. compartment
    end
    if protection ~= nil and protection ~= "" then
      if filter == "" then filter = "?" else filter = filter.."&" end
      filter = filter .."protectionMode=".. protection
    end
    if algo ~= nil and algo ~= "" then
      if filter == "" then filter = "?" else filter = filter.."&" end
      filter = filter .."algorithm=".. algo
    end
  end
  if vault_endpoint ~= nil and vault_endpoint ~= "" then
    vault_prefix = vault_endpoint.."-management"
  end
  
  local response, err = oci_request(secret_id, region, target..filter, body, method)
  if response ~= nil then
    return response, nil
  end
  return response, err
end

------------------------------------------------------------------------------------

function check(input)
  if input.secret_id ~= nil then
    local secret, err = Sobject { id = input.secret_id }
    if secret ~= nil then 
        tenant = secret.custom_metadata['TenantOCID']
        user = secret.custom_metadata['UserOCID']
    end
    if (tenant == nil or tenant == "") and input.secret_key ~= nil then
      tenant = input.ocids.tenant
    end
    if input.region == nil or input.region == "" then
      input.region = secret.custom_metadata['Region']
    end
    if input.region == nil or input.region == "" then input.region = default_region end
  end
end

function run(input)

  if input.operation == "configure" then  
    local oci_secret, err = configure_secret(input.secret_key, input.fingerprint, input.ocids.tenant, input.ocids.user, input.region, input.ocids.compartment, input.vault)
    return {secret_id = oci_secret.kid}
    
  elseif input.operation == "check" then
    vault = ""
    vaults, err = oci_op(input.secret_id, "", input.region, "GET", input.compartment, "vaults")
    return vaults, err

  elseif input.operation == "list" then
    keys, err = oci_op(input.secret_id, "", input.region, "GET", input.compartment, "keys", input.vault, input.protection, input.algo)
    if keys == nil then
      return { result = keys, error = err, message = input.operation..": OCI BYOK list keys operation failed"}
    end
    return keys

  elseif input.operation == "get" or input.operation == "getversion" or
    input.operation == "getversions"  then
    local url_suffix = ""
    if input.operation == "getversion" then
      url_suffix = "/keyVersions/"..input.version
    elseif input.operation == "getversions" then
      url_suffix = "/keyVersions"
    end
    key, err = oci_op(input.secret_id, "", input.region, "GET", input.compartment, "keys/"..input.key..url_suffix, input.vault)
    if key == nil then
      return { result = key, error = err, message = input.operation..": OCI BYOK get key operation failed"}
    end
    return key

  elseif input.operation == "disable" or input.operation == "enable" then
    key, err = oci_op(input.secret_id, "", input.region, "POST", "", "keys/"..input.key.."/actions/"..input.operation, input.vault)
    if key == nil then
      return { result = key, error = err, message = input.operation..": OCI BYOK disable key operation failed"}
    end
    return key

  elseif input.operation == "delete" or input.operation == "undelete" or
    input.operation == "deleteversion" or input.operation == "undeleteversion" then
    local url_suffix = ""
    if input.operation == "deleteversion" or input.operation == "undeleteversion"  then
      url_suffix = "/keyVersions/"..input.version
    end
    local body = ""
    if input.operation == "delete" or input.operation == "deleteversion" then
      input.operation = "scheduleDeletion" 
      local tnow = Time.now_insecure()
      if input.expiry ~= nil and input.expiry ~= "" then
      else input.expiry = 7 end
      local texp = tnow:add_seconds(tonumber(input.expiry)*24*3600):to_iso8601()
      local jexp = { timeOfDeletion = to_rfc3339(texp) }
      body = json.encode(jexp)
    else input.operation = "cancelDeletion" end

    key, err = oci_op(input.secret_id, body, input.region, "POST", "", "keys/"..input.key..url_suffix.."/actions/"..input.operation, input.vault)
    if key == nil then
      return { result = key, error = err, message = input.operation..": OCI BYOK scheduled key operation failed"}
    end
    return key

  elseif input.operation == "import" then
    local body = {}
    if input.compartment == nil or input.compartment == "" then
      body["compartmentId"] = assert(Sobject{id=input.secret_id}).custom_metadata['CompartmentOCID']
    end
    if input.protection ~= nil and input.protection ~= "" then
      body.protectionMode=input.protection
    end
    if input.free_tags ~= nil then
      body.freeformTags = input.free_tags
    end
    -- lookup and wrap the key with OCI vault pub key
    if input.name == nil and input.name == "" then
      input.name = "oci-import."..Blob.random { bits = 32 }:hex()
    end
    body.displayName = input.name

    local sobj = Sobject{id = input.name}
    if sobj == nil then sobj = Sobject{name = input.name} end
    if sobj == nil then
      sobj = assert(Sobject.create { name=input.name, obj_type=input.type, 
          key_size=input.size, key_ops={"EXPORT"} })
    end
    assert(sobj.obj_type == input.type and sobj.key_size == input.size )
    body.externalKeyReference = sobj.kid

    local vault_wrapper = oci_op(input.secret_id, "", input.region, "GET", input.compartment, "wrappingKeys", input.vault)
    local trans_rsa = assert(Sobject.import { transient=true, obj_type="RSA", value=
        vault_wrapper.publicKey:gsub('BEGIN PUBLIC KEY',''):gsub('\n',''):gsub('END PUBLIC KEY',''):gsub('-','') })

    -- TBD.. RSA_OAEP_AES_SHA256 needed for RSA import
    body.wrappedImportKey = { wrappingAlgorithm = "RSA_OAEP_SHA256",
      keyMaterial=assert(trans_rsa:wrap { subject = sobj, mode = 'OAEP_MGF1_SHA256' }).wrapped_key }
    AuditLog.log { message = sobj.kid .. " was wrapped with a transient key: "..
      trans_rsa.obj_type .."/"..trans_rsa.key_size.."/", severity = "INFO" }

    body.keyShape = { algorithm=input.type, length=tonumber(input.size/8)}

    key, err = oci_op(input.secret_id, json.encode(body), input.region, "POST", "", "keys/"..input.operation, input.vault)
    if key == nil then
      return { result = key, error = err, message = input.operation..": OCI BYOK import key operation failed"}
    end
    return key

  elseif input.operation == "rotate" or input.operation == "importversion" then
    local body = {}
    -- lookup and wrap the key with OCI vault pub key
    if input.name == nil and input.name == "" then
      return nil, "Need a DSM key name or UUID to lookup for rotate"
    end

    local sobj = Sobject{id = input.name}
    if sobj == nil then sobj = Sobject{name = input.name} end    
    -- lookup key in OCI and reconstruct new locally
    oci_key, err = oci_op(input.secret_id, "", input.region, "GET", input.compartment, "keys/"..input.key, input.vault)
    if oci_key == nil then
      return { result = oci_key, error = err, message = input.operation..": OCI BYOK get key operation failed"}
    end
    
    if sobj == nil then
      input.name = oci_key.displayName
      sobj = assert(Sobject.create { name=input.name, obj_type=oci_key.keyShape.algorithm, 
          key_size=oci_key.keyShape.length*8, key_ops={"EXPORT"} })
    elseif input.operation == "rotate" then
      sobj = assert(sobj:rekey { name=input.name, obj_type=oci_key.keyShape.algorithm, 
          key_size=oci_key.keyShape.length*8, key_ops={"EXPORT"} })
    end

    local vault_wrapper = oci_op(input.secret_id, "", input.region, "GET", input.compartment, "wrappingKeys", input.vault)
    local trans_rsa = assert(Sobject.import { transient=true, obj_type="RSA", value=
        vault_wrapper.publicKey:gsub('BEGIN PUBLIC KEY',''):gsub('\n',''):gsub('END PUBLIC KEY',''):gsub('-','') })

    -- TBD.. RSA_OAEP_AES_SHA256 needed for RSA import
    body.wrappedImportKey = { wrappingAlgorithm = "RSA_OAEP_SHA256",
      keyMaterial=assert(trans_rsa:wrap { subject = sobj, mode = 'OAEP_MGF1_SHA256' }).wrapped_key }
    AuditLog.log { message = sobj.kid .. " was wrapped with a transient key: "..
      trans_rsa.obj_type .."/"..trans_rsa.key_size.."/", severity = "INFO" }

    key, err = oci_op(input.secret_id, json.encode(body), input.region, "POST", "", "keys/"..input.key.."/keyVersions/import", input.vault)
    if key == nil then
      return { result = key, error = err, message = input.operation..": OCI BYOK rotate key operation failed"}
    end
    return key
    
  else
    return nil, "Specify a valid operation"
  end -- operation switch
end

