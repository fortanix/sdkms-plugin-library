-- Name: Key/Value Pair
-- Version: 1.0
-- Description:## Short Description
-- Seamlessley extend the functionality of Fortanix Self Defending KMS Secrets. Leverage applications generate and manage key-value (KV) pairs through Self Defending KMS Secrets.
--
-- ### ## Introduction
-- Every day, application teams come to rely on numerous secrets in their development and operational (DevOps) processes. Secrets ranging from passwords, tokens, certificates, SSH keys and database credentials simply cannot be hard-coded or statically configured. 
-- 
-- **Fortanix Self Defending KMS is THE MOST SECURE KMS** in the market. With this Plugin, DevOps can now easily manage their build and deployment secrets to maintain confidentiality throughout their CI/CD pipelines as well as during application runtime.
-- 
-- ### Use cases
-- 
-- * Set and retrieve keys and corresponding values
--     - keys and values are comma-separated parameters inside JSON
-- 
-- * Namespace support prevents secret path collisions
--     - names of Self Defending KMS Secrets are unique within an Self Defending KMS Account
--     - Plugin prefixes KV secrets paths with a namespace to allow path reuse
--     - allows multiple secrets with the same path inside an Self Defending KMS Account
-- 
-- * Versioning support for keys such that:
--     - Key update/delete automatically creates a new version
--     - Key update/delete does not delete other keys
--     - Uses Self Defending KMS custom metadata to validate versions
-- 
-- * Deletion truncates the latest version (LIFO) or purges all versions
-- 
-- ## Setup and Usage
-- ### Invoking Plugins from Self Defending KMS CLI
-- Check the Self Defending KMS Python-based CLI README for information on setting up the CLI.
-- 
-- * Log in to Self Defending KMS first.  `$ sdkms-cli user-login`
--     - Currently, the CLI only allows `user-login` for Plugin invocation.
--     - Specify an account argument if user has access to multiple accounts:
--         - `--account-name`
-- * Invoke the Plugin:
-- `$ sdkms-cli invoke-Plugin --name kvp --in <read-secret-kvp.json>`
--     - Either of the following argument should work:
--         - `--name` 
--         - `--id` 
--     - `in` : Path to input JSON file.
-- 
-- 
-- ## Input and Output JSON Formats
-- The following sections specify the fields in the inputs and outputs of the
-- Plugin's operations, which are JSON maps.
-- 
-- __Important note__ about some of the input JSON parameters:
-- 
-- * `group` : string, the prefix of the KVP secret.
--     - Can be some arbitrary namespace label or an Self Defending KMS Group UUID.
--     - In case a Group UUID is specified, KVP secret creation will be attempted in that Group.
--     - The Plugin also needs to be a member of the specified Self Defending KMS Group.
-- * `path` : string, the label of the KVP secret.
--     - If `group` isn't specified, then the path needs to be unique within the entire Self Defending KMS Account.
-- 
-- 
-- ###  GET Operation
-- #### Input
-- * `op` : string, must be = `get` for reading a specific KVP secret.
-- * `group` : string, the prefix of the KVP secret. ***Optional***.
-- * `path` : string, the label of the KVP secret. **Required**
-- * `version` : string, version of the KVP secret. ***Optional***.
-- * `keys` : string, comma-separated list of key labels. ***Optional***.
-- 
-- #### Output
-- * `v#` : string, version number of the KVP secret.
--     * [array] containing all key-value pairs or those matching the input keys, if specified:
--         - `<key_name>`: string, JSON record index.
--         - `<key_value>`: string, JSON record value.
-- 
-- ### PUT Operation
-- #### Input
-- * `op` : string, must be = `put` for writing a specific KVP secret.
-- * `group` : string, the prefix of the KVP secret. ***Optional***.
-- * `path` : string, the label of the KVP secret. **Required**
-- * `keys` : string, comma-separated list of key labels. **Required**.
-- * `values` : string, a comma-separated list of key values. **Required**.
-- 
-- #### Output
-- * `v#` : string, the version number of the KVP secret. **Auto-incremented**.
--     * [array] containing all key-value pairs that match the input keys as well as those preexisting :
--         - `<key_name>`: string, JSON record index.
--         - `<key_value>`: string, JSON record value.
-- 
-- ### DEL Operation
-- #### Input
-- * `op` : string, must be = `put` for dropping a key within a specific KVP secret.
-- * `group` : string, the prefix of the KVP secret. ***Optional***.
-- * `path` : string, the label of the KVP secret. **Required**
-- * `keys` : string, comma-separated list of key labels. **Required**.
-- 
-- #### Output
-- * `v#` : string, the version number of the KVP secret. **Auto-incremented**.
--     * [array] containing all key-value pairs excluding the keys specified:
--         - `<key_name>`: string, JSON record index.
--         - `<key_value>`: string, JSON record value.
-- 
-- ### DEBUG Operation
-- #### Input
-- * `op` : string, must be = `debug` for displaying all the versions of a specific KVP secret.
-- * `group` : string, the prefix of the KVP secret. ***Optional***.
-- * `path` : string, the label of the KVP secret. **Required**
-- * `keys` : string, comma-separated list of key labels. ***Optional***.
-- 
-- #### Output
-- *  [array] containing **all versions** of the KVP secret:
--    - `v#` : string, the version number of the KVP secret.
--     * [array] containing all key-value pairs excluding the keys specified :
--         - `<key_name>`: string, JSON record index.
--         - `<key_value>`: string, JSON record value.
-- 
-- ### TERMINATE Operation
-- __Note__: All versions are deleted and the operation is audited.
-- #### Input
-- * `op` : string, must be = `ter` for completely destroying a specific KVP secret.
-- * `group` : string, the prefix of the KVP secret. ***Optional***.
-- * `path` : string, the label of the KVP secret. **Required**
-- 
-- #### Output
-- *  `message`: [string] error or success.
-- 
-- ## Testing
-- 
-- Following example shows the lifecycle of a KVP secret as each operation is performed through the KVP Plugin.
-- 
-- * `op:put` creates new key(s) 
--     - Version: new >> v1
--     - Input: `{op:put, [k1], [val1]}`
--     - Output: `v1{[k1:val1]}`
-- * `op:put` updates and/or adds new key(s)
--     - Version: v1 >> v2 
--     - Input `{op:put, keys:k1,k2, values:v1,v2}`
--     - Output: `v2{[k1:v1,k2:v2]}`
-- * `op:del` removes a key and bumps up version
--     - Version: v2 >> v3
--     - Input: `{op:del, keys: k2}`
--     - Output: `v3{[k1:v1]}`
-- * `op:put` increments always version
--     - Version: v3 >> v4
--     - Input: `{op:put, keys:k3, values:val3}`
--     - Output: `v4{[k1:v1,k3:val3]}`
-- * `op:debug` returns all versions and filters by key(s)
--     - Versions: v1 <<>> v4: 
--     - Input: `{op:debug, keys:k1}`
--     - Output: `v1{[k1:val1]}, v2([k1:v1]}, v3{[k1:v1]}, v4{[k1:v1]}`
-- * `op:ter`destroys the KV secret altogether
--     - Versions: `{[v4,v3,v2,v1]}` >> destroyed
--     - Output: error or success message
-- 
-- 
-- ## Room for Improvement
-- Following use cases are not supported yet:
-- 
--   * alternative storage to Self Defending KMS Opaque Security Objects
--   * explicit auditing with fine-grained levels
--   * deletion of specific version and linking adjacent versions
--   * revert to version and truncate all future version
-- 
-- Community improvements are welcome. Join us on [Slack](https://fortanix.com/community/).
-- Get your **API KEY** by signing up at [sdkms.fortanix.com](https://sdkms.fortanix.com).
-- 
-- ## References
-- * [support.fortanix.com/sdkms/developers-guide-Plugin.html](https://support.fortanix.com/sdkms/developers-guide-Plugin.html "Self Defending KMS developers guide Plugin")
-- * [support.fortanix.com/api/#/Plugins](https://support.fortanix.com/api/#/Plugins "Self Defending KMS Plugins API")
-- * [bitbucket.org/fortanix/kubernetes-integration](https://bitbucket.org/fortanix/kubernetes-integration "Kubernetes Integration")
-- 
-- ### Release Notes
-- - Initial Release
--     - Uses Self Defending KMS Secret Security Object
--     - Self Defending KMS Secrets are fully audited
--     - Storage of KVPs limited to 1024 bytes
--     - Test script provided
--     - Tested with **Kubernetes Secrets Injection** referenced above.

--[[
{
  "op": "put",
  "path": "secret/test1",
  "group": "namespace",
  "keys": "key1,key2,key3",
  "values": "top-secret,zooom,vroom"
}
{
  "op": "del",
  "path": "secret/test1",
  "group": "namespace",
  "keys": "key1"
}
{
  "op": "get",
  "path": "secret/test1",
  "group": "namespace",
  "keys": "key6,key3,key1",
  "version": "1"
}
{
  "op": "put",
  "path": "secret/test1",
  "group": "namespace",
  "keys": "key4,key2",
  "values": "an0th3rsecc,cha@g3d"
}
{
  "op": "debug",
  "path": "secret/test1",
  "group": "namespace",
  "keys": "key1",
}
{
  "op": "ter",
  "path": "secret/test1",
  "group": "namespace",
  "version": "2",
}

--]]
local EMPTY = ""
local ALL_KEYS = "#LIST_ALL"

function run(input)
  if     input.op == 'get' then return get_secret(input)
  elseif input.op == 'put' then return put_secret(input)
  elseif input.op == 'del' then return del_secret(input)
  elseif input.op == 'ter' then return del_secret(input, true, true)
  elseif input.op == 'debug' then return sho_secret(input)
  --elseif input.op == 'rem' then return del_secret(input, true, false)
  else return nil, 'Invalid operation or input'   end
end

function lookup_sobject(input, failonlookup)
  assert(input.path)
  local name = input.group
  if name == nil then name = input.path
  else name = name .. ":" .. input.path  end
  local vers = nil
  if input.version ~= nil and input.version ~= EMPTY then 
    vers = tonumber(input.version)
    assert(vers ~= nil and vers > 0)
    name = name .. ":version_" .. input.version
    if vers > 1 then
       --name = name .. ":version_" .. input.version
    end
  end
  local sobj = nil
  if failonlookup then sobj = assert(Sobject { name = name })
  else sobj = Sobject { name = name } end

  if sobj ~= nil then
    if vers ~= nil then
      local attrib = sobj.custom_metadata -- TEMP
      if attrib ~= nil and attrib['version'] ~= nil then
        if failonlookup then assert(vers == tonumber(attrib['version'])) end
      end
    end
    return sobj
  end
  return nil
  --return name .. ", vers=" .. tostring(vers) .. ", objvers=" .. sobj.custom_metadata['version']
end

function sho_secret(input)
  
  local secret = lookup_sobject(input, false)
  local resp = {}
  if secret ~= nil then 
    local latest = 1
    local attrib = secret.custom_metadata -- TEMP
    if attrib == nil or attrib['version'] == nil then latest = 1
    else latest = tonumber(attrib['version']) end

    table.insert(resp, get_secret(input))
    for i=latest-1,1,-1 do 
      input['version'] = tostring(i)
      table.insert(resp, get_secret(input))
    end
  end
  return resp
end

function del_secret(input, force, all_versions)

  local latest = 1
  local old_secret = lookup_sobject(input, true)
  if input.op == "del" and input.version and input.version ~= EMPTY and tonumber(input.version) > 0 then return "Invalid parameters" end
  local attrib = old_secret.custom_metadata -- TEMP
  if attrib == nil or attrib['version'] == nil then latest = 1
  else latest = tonumber(attrib['version']) end

  if force == nil or force ~= true then
    if old_secret then
      local name = old_secret.name
      
      -- -- assert(old_secret:delete()) -- throw an exception if delete fails
      assert(old_secret:update{ name = name .. ":version_" .. latest, enabled = true}) -- throw an exception if update fails

      local secret_obj = {}
      local exported_value = assert(old_secret:export().value)
      if input.keys ~= EMPTY then
        local kv_pairs = json.decode(string.sub(exported_value[1],string.find(exported_value[1], '{'),string.len(exported_value[1])))
        local sel_keys = requested_keys(input, false)
        secret_obj = filter_list(kv_pairs, sel_keys, true, true)
      end
      local secret_value = json.encode(secret_obj)

      -- mystery: sometimes the above update takes long and is ASYNC, causing duplicate sObject error in creation blow
      assert(old_secret:update{ name = name .. ":version_" .. latest, enabled = false}) -- throw an exception if update fails

      latest = latest + 1
      attrib['version'] = tostring(latest)
      local new_secret, error = Sobject.import{ name = name, obj_type = "SECRET", value = cbor.encode(secret_value), group_id = input.group, custom_metadata = attrib}
      if new_secret == nil then
        if error and error.status == 400 then
          -- error.message == "CBOR error: custom error: Invalid length; expecting 32 or 36 chars, found XXX"
          new_secret = assert(Sobject.import{ name = name, obj_type = "SECRET", value = cbor.encode(secret_value), custom_metadata = attrib})
        end
      end
      local resp = {}
      resp["v"..latest] = secret_obj
      return resp
      -- return new_secret
    end
    
  elseif force == true then
    local input_copy = input
    -- delete a specific version or entire secret = testing TBD
    if all_versions ~= nil and all_versions == true then
      for i=latest-1,1,-1 do 
        input_copy['version'] = tostring(i)
        local prev_secret = lookup_sobject(input_copy, false)
        if prev_secret ~= nil then 
          prev_secret:delete() -- do NOT throw an exception if iterative delete fails
        end
      end
    end
    assert(old_secret:delete()) -- throw an exception if delete fails
    local resp = {}
    resp["STATUS"] = "Delete successful"
    return resp
  end
end

function put_secret(input)
  --assert(input.version == nil or input.version == EMPTY)
  if input.version and input.version ~= EMPTY and tonumber(input.version) > 0 then return "Invalid parameters" end
  assert(input.keys)
  assert(input.values)
  if input.keys == EMPTY or input.values == EMPTY then return "Invalid parameters" end
  local name = EMPTY
  local exported_value = {}
  local kv_pairs = {}
  local latest = 1
  local attrib = {}
  local old_secret = lookup_sobject(input, false)
  if old_secret then
    name = old_secret.name
    exported_value = assert(old_secret:export().value)
    attrib = old_secret.custom_metadata -- TEMP
    if attrib == nil or attrib['version'] == nil then latest = 1
    else latest = tonumber(attrib['version']) end
    -- -- assert(old_secret:delete()) -- throw an exception if delete fails
    assert(old_secret:update{ name = name .. ":version_" .. latest, enabled = false}) -- throw an exception if update fails
    kv_pairs = json.decode(string.sub(exported_value[1],string.find(exported_value[1], '{'),string.len(exported_value[1])))
    latest = latest + 1
  else
    if input.group ~= nil then name = input.group..":"..input.path 
    else name = input.path end
  end
  local keys = requested_keys(input, true)
  local vals = {}
  if input.values ~= nil then vals = str_split(input.values) end
  
  secret_obj = filter_list(kv_pairs, keys, true, false, vals)
  secret_value = json.encode(secret_obj)
  attrib['version'] = tostring(latest)
  local new_secret, error = Sobject.import{ name = name, obj_type = "SECRET", value = cbor.encode(secret_value), group_id = input.group, custom_metadata = attrib}
  if new_secret == nil then
    if error ~= nil and error.status == 400 then
      -- error.message == "CBOR error: custom error: Invalid length; expecting 32 or 36 chars, found XXX"
      new_secret = Sobject.import{ name = name, obj_type = "SECRET", value = cbor.encode(secret_value), custom_metadata = attrib}
    end
  end
  
  local resp = {}
  resp["v"..latest] = secret_obj
  return resp
end

function get_secret(input)
  if (input.keys == nil or input.keys == EMPTY or input.keys == ALL_KEYS) then all = true end

  local secret = lookup_sobject(input, true)
  local latest = 1
  attrib = secret.custom_metadata -- TEMP  
  if attrib == nil or attrib['version'] == nil then latest = 1  
  else latest = tonumber(attrib['version']) end
  
  if input.version ~= nil and input.version ~= EMPTY and tonumber(input.version) > 0 then
      assert(secret:update{ enabled = true}) -- throw an exception if update fails
  end
  local exported_value = assert(secret:export().value)
  if input.version ~= nil and input.version ~= EMPTY and tonumber(input.version) > 0 then
      assert(secret:update{ enabled = false}) -- throw an exception if update fails
  end
  -- mystery: json_encode or cbor_encode inserts abitrary characters at beginning during save, so find seems unreliable?
  local start = string.find(exported_value[1], '{')
  if type(start) == "nil" then
    local resp = {}
    resp["STATUS"] = "Invalid key-value pairs"
    return resp
  end
  local kv_pairs = json.decode(string.sub(exported_value[1], start, string.len(exported_value[1])))
  local keys = requested_keys(input, all)
  if keys[1] == ALL_KEYS then all = true end
   
  secret_obj = filter_list(kv_pairs, keys, all)
  local resp = {}
  resp["v"..latest] = secret_obj
  return resp
end

function requested_keys(input, all)
  local keys = {}
  if input.keys ~= nil and input.keys ~= EMPTY then keys = str_split(input.keys) end
  local next = next
  if all == true and next(keys) == nil then table.insert(keys, ALL_KEYS) end -- no specific keys requested 
  return keys
end

function filter_list(haystack, needle, all, inverse, values)
  local resp = {}
  local next = next
  if type(haystack) == 'table' then
    for k,v in pairs(haystack) do
      exists = has_value(needle, k)
      if exists > 0 then
        if inverse == nil or inverse == false then 
          if values ~= nil then resp[k] = values[exists]
          else resp[k] = v end
        end
      elseif inverse == true or all == true then
        resp[k] = v
      end
    end
  end
  if all == true and values ~= nil then
    for i,k in pairs(needle) do
      resp[k] = values[i]
    end
  end
  return resp
end

function str_split (inputstr, sep)
  if sep == nil then sep = "," end
  local t={}
  for str in string.gmatch(inputstr, "([^"..sep.."]+)") do table.insert(t, str) end
  return t
end

function has_value (tab, val)
  assert(val)
  for index, value in ipairs(tab) do
    if value == val then return index end
  end
  return 0
end

