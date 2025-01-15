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

local function expect_required_fields(obj, field_names_and_types)
  for _, field in pairs(field_names_and_types) do
    if not obj[field["name"]] then
      return Error.new("missing required field `" .. field.name .. "`")
    end
    if type(obj[field["name"]]) ~= field["type"] then
      return Error.new("invalid value for `" .. field.name .. "`, expected a " .. field["type"])
    end
  end
  return nil
end

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
    return nil, err
  end

  sobject_template["value"] = key_bytes

  local imported, err = Sobject.import(sobject_template)
  if err ~= nil then
    return nil, err
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
  local kbpk, err = Sobject { kid = kbpk_id }
  if err ~= nil then return nil, Error.new("KBPK Sobject does not exist") end
  if kbpk.obj_type ~= KBPK_OBJ_TYPE_AES or kbpk.key_size ~= KBPK_KEY_SIZE then
    return nil, Error.new("KBPK needs to be of type " .. KBPK_OBJ_TYPE_AES .. KBPK_KEY_SIZE)
  end
  return kbpk, nil
end

local function check_header(header)
  if type(header) ~= "table" then
    return Error.new("'header' must be a Lua table")
  end

  local header_required_fields = {
    { name = LABEL_HEADER_VERSION,            type = "string" },
    { name = LABEL_HEADER_KEY_USAGE,          type = "string" },
    { name = LABEL_HEADER_ALGORITHM,          type = "string" },
    { name = LABEL_HEADER_MODE_OF_USE,        type = "string" },
    { name = LABEL_HEADER_KEY_VERSION_NUMBER, type = "string" },
    { name = LABEL_HEADER_EXPORTABILITY,      type = "string" },
    { name = LABEL_HEADER_KEY_CONTEXT,        type = "string" }
  }
  return expect_required_fields(header, header_required_fields)
end

----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
-----------     Plugin entrypoint     -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
function run(input)
  -- Check input
  if type(input) ~= "table" then
    return nil, Error.new("'input' must be a Lua table")
  end
  if not input[LABEL_OPERATION] then
    return nil, Error.new("missing argument: " .. LABEL_OPERATION)
  end

  local operation = input[LABEL_OPERATION]

  local required_fields, target_or_cryptogram, header, sobject_template
  if operation == LABEL_OPERATION_OPEN then
    required_fields = {
      { name = LABEL_KBPK_ID,          type = "string" },
      { name = LABEL_CRYPTOGRAM,       type = "string" },
      { name = LABEL_SOBJECT_TEMPLATE, type = "table" }
    }
    target_or_cryptogram = input[LABEL_CRYPTOGRAM]
    sobject_template = input[LABEL_SOBJECT_TEMPLATE]
  elseif operation == LABEL_OPERATION_SEAL then
    required_fields = {
      { name = LABEL_KBPK_ID,   type = "string" },
      { name = LABEL_TARGET_ID, type = "string" },
      { name = LABEL_HEADER,    type = "table" }
    }
    target_or_cryptogram = input[LABEL_TARGET_ID]
    header = input[LABEL_HEADER]
  else
    return Error.new("unknown operation " .. operation)
  end

  local err = expect_required_fields(input, required_fields)
  if err ~= nil then
    return nil, err
  end

  local kbpk, err = check_kbpk(input[LABEL_KBPK_ID])
  if err ~= nil then
    return nil, err
  end

  -- Operate
  if operation == LABEL_OPERATION_OPEN then
    return open(kbpk, target_or_cryptogram, sobject_template)
  elseif operation == LABEL_OPERATION_SEAL then
    local err = check_header(header)
    if err ~= nil then
      return nil, err
    end
    local target = Sobject { kid = target_or_cryptogram }
    if target == nil then
      return Error.new("Target Sobject does not exist")
    end
    return seal(kbpk, header, target)
  end
end
