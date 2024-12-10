-- Constants
local KBPK_OBJ_TYPE_AES               = "AES"
local KBPK_KEY_SIZE                   = 256
local LABEL_CRYPTOGRAM                = "cryptogram"
local LABEL_HEADER                    = "header"
local LABEL_KBPK_ID                   = "key_block_protection_key_id"
local LABEL_OPERATION                 = "operation"
local LABEL_OPERATION_OPEN            = "open"
local LABEL_OPERATION_SEAL            = "seal"
local LABEL_TARGET_ID                 = "target_key_id"
local LABEL_HEADER_VERSION            = "version"
local LABEL_HEADER_KEY_USAGE          = "key_usage"
local LABEL_HEADER_ALGORITHM          = "algorithm"
local LABEL_HEADER_MODE_OF_USE        = "mode_of_use"
local LABEL_HEADER_KEY_VERSION_NUMBER = "key_version_number"
local LABEL_HEADER_EXPORTABILITY      = "exportability"
local LABEL_HEADER_KEY_CONTEXT        = "key_context"
local LABEL_SOBJECT_TEMPLATE          = "sobject_template"

local ALG_TO_OBJ_TYPE = {
  A     = "AES",
  D     = "DES",
  E     = "EC",
  H     = "HMAC",
  R     = "RSA",
  S     = "DSA",
  T     = "DES3",
  OTHER = "SECRET"
}

local function open(kbpk, cryptogram, sobject_template)
  local alg = string.sub(cryptogram, 8, 8)
  local exportability = string.sub(cryptogram, 9, 9)
  local obj_type = ALG_TO_OBJ_TYPE[alg]
  if obj_type == nil then
    obj_type = ALG_TO_OBJ_TYPE["OTHER"]
  end

  sobject_template["obj_type"] = obj_type
  if sobject_template["key_ops"] == nil then
    sobject_template["key_ops"] = {}
  end
  if exportability == "E" or exportability == "S" then
    table.insert(sobject_template["key_ops"], "EXPORT")
  end

  -- The actual unwrapping
  local key_bytes, err = tr31_open(kbpk, cryptogram)
  if err ~= nil then
    return { error = err }
  end

  sobject_template["value"] = key_bytes

  local imported, err = Sobject.import(sobject_template)
  if err ~= nil then
    return { error = err }
  end

  return imported, nil
end

local function seal(kbpk, header, target)
  local e = Tr31Envelope.new(header.version,
                             header.key_usage,
                             header.algorithm,
                             header.mode_of_use,
                             header.key_version_number,
                             header.exportability,
                             header.key_context)
  return e:seal(kbpk, target)
end

local function check_kbpk(kbpk_id)
  local kbpk = assert(Sobject { kid = kbpk_id }, "KBPK Sobject does not exist")
  if kbpk.obj_type ~= KBPK_OBJ_TYPE_AES or kbpk.key_size ~= KBPK_KEY_SIZE then
    return nil, "KBPK needs to be of type " .. KBPK_OBJ_TYPE_AES .. KBPK_KEY_SIZE
  end
  return kbpk, nil
end

function check_header(header)
  if type(header) ~= "table" then
    return nil, "'header' must be a Lua table"
  end

  local header_required_fields = {
    LABEL_HEADER_VERSION,
    LABEL_HEADER_KEY_USAGE,
    LABEL_HEADER_ALGORITHM,
    LABEL_HEADER_MODE_OF_USE,
    LABEL_HEADER_KEY_VERSION_NUMBER,
    LABEL_HEADER_EXPORTABILITY,
    LABEL_HEADER_KEY_CONTEXT
  }
  for _, field in pairs(header_required_fields) do
    if not header[field] then
      error("missing header." .. field)
    end
  end

  return header, nil
end

function check_target(target_key_id)
  local target = assert(Sobject { kid = target_key_id }, "Target Sobject does not exist")
  return target, nil
end

----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
-----------     Plugin entrypoint     -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
function run(input)
  -- Check input
  if not input[LABEL_OPERATION] then
    error("missing argument: " .. LABEL_OPERATION)
  end

  local operation = input[LABEL_OPERATION]

  local required_fields, target_or_cryptogram, header, sobject_template
  if operation == LABEL_OPERATION_OPEN then
    required_fields = { LABEL_KBPK_ID, LABEL_CRYPTOGRAM, LABEL_SOBJECT_TEMPLATE }
    target_or_cryptogram = input[LABEL_CRYPTOGRAM]
    sobject_template = input[LABEL_SOBJECT_TEMPLATE]
  elseif operation == LABEL_OPERATION_SEAL then
    required_fields = { LABEL_KBPK_ID, LABEL_TARGET_ID, LABEL_HEADER }
    target_or_cryptogram = input[LABEL_TARGET_ID]
    header = input[LABEL_HEADER]
  end
  for _, field in pairs(required_fields) do
    if not input[field] then
      error("missing argument '" .. field .. "' for " .. operation .. " operation")
    end
  end
  local kbpk, err = check_kbpk(input[LABEL_KBPK_ID])
  if err ~= nil then
    return { error = err }
  end

  -- Operate
  if operation == LABEL_OPERATION_OPEN then
    return open(kbpk, target_or_cryptogram, sobject_template)
  elseif operation == LABEL_OPERATION_SEAL then
    local header_checked, err = check_header(header)
    if err ~= nil then
      return { error = err }
    end
    local target, err = check_target(target_or_cryptogram)
    if err ~= nil then
      return { error = err }
    end
    return seal(kbpk, header_checked, target)
  else
    return { error = "unknown operation " .. operation }
  end
end
