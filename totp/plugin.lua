
-- TOTP URLs will contain this value as `issuer`
local totp_issuer = "Fortanix DSM"
-- Security objects created for each account will have this prefix in their name
local totp_name_prefix = "totp/"

-- A trimmed down copy of basexx library, taken from:
-- https://github.com/aiq/basexx/blob/v0.4.1/lib/basexx.lua

local basexx = {}

local function divide_string(str, max)
  local result = {}
  local start = 1
  for i = 1, #str do
     if i % max == 0 then
        table.insert(result, str:sub(start, i))
        start = i + 1
     elseif i == #str then
        table.insert(result, str:sub(start, i))
     end
  end
  return result
end

local function number_to_bit(num, length)
  local bits = {}
  while num > 0 do
     local rest = math.floor(math.fmod(num, 2))
     table.insert(bits, rest)
     num = (num - rest) / 2
  end

  while #bits < length do
     table.insert(bits, "0")
  end
  return string.reverse(table.concat(bits))
end

local function ignore_set(str, set)
  if set then str = str:gsub("["..set.."]", "") end
  return str
end

local function pure_from_bit(str)
  return ( str:gsub( '........', function (cc) return string.char(tonumber(cc, 2)) end) )
end

local function unexpected_char_error(str, pos)
  local c = string.sub(str, pos, pos)
  return string.format("unexpected character at position %d: '%s'", pos, c)
end

function basexx.to_bit(str)
  local sub_fn = function(c)
    local byte = string.byte(c)
    local bits = {}
    for _ = 1,8 do
       table.insert(bits, byte % 2)
       byte = math.floor(byte / 2)
    end
    return table.concat(bits):reverse()
  end
  return ( str:gsub('.', sub_fn) )
end

local function from_basexx(str, alphabet, bits)
  local result = {}
  for i = 1, #str do
     local c = string.sub(str, i, i)
     if c ~= '=' then
        local index = string.find(alphabet, c, 1, true)
        if not index then
           return nil, unexpected_char_error(str, i)
        end
        table.insert(result, number_to_bit(index - 1, bits))
     end
  end
  local value = table.concat(result)
  local pad = #value % 8
  return pure_from_bit(string.sub(value, 1, #value - pad))
end

local function to_basexx(str, alphabet, bits, pad)
  local bitString = basexx.to_bit(str)
  local chunks = divide_string(bitString, bits)
  local result = {}
  for _,value in ipairs(chunks) do
     if ( #value < bits ) then
        value = value .. string.rep('0', bits - #value)
     end
     local pos = tonumber(value, 2) + 1
     table.insert(result, alphabet:sub(pos, pos))
  end
  table.insert(result, pad)
  return table.concat(result)
end

local base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
local base32PadMap = { "", "======", "====", "===", "=" }

function basexx.from_base32(str, ignore)
  str = ignore_set(str, ignore)
  return from_basexx(string.upper(str), base32Alphabet, 5)
end

function basexx.to_base32(str)
  return to_basexx(str, base32Alphabet, 5, base32PadMap[ #str % 5 + 1 ])
end

local base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local base64PadMap = { "", "==", "=" }

function basexx.from_base64(str, ignore)
   str = ignore_set(str, ignore)
   return from_basexx(str, base64Alphabet, 6)
end

function basexx.to_base64(str)
   return to_basexx(str, base64Alphabet, 6, base64PadMap[ #str % 3 + 1 ])
end

-- OTP library adapted to use DSM for crypto
-- Source: https://github.com/remjey/luaotp/blob/v0.1-6/src/otp.lua

local otp = {}

local unpack = unpack or table.unpack

local metadata_format_version = 1
local default_key_length = 15
local default_hash_algorithm = "SHA1"
local default_digits = 6
local default_period = 30
local default_totp_deviation = 5

-- Formats a counter to a 8-byte string
local function counter_format(n)
  local rt = { 0, 0, 0, 0, 0, 0, 0, 0 }
  local i = 8
  while i > 1 and n > 0 do
    rt[i] = n % 0x100
    n = math.floor(n / 0x100)
    i = i - 1
  end
  return string.char(unpack(rt))
end

-- Generates a one-time password based on a key and a counter
local function generate_password(key_name, counter, digits, hash_alg)
  local c = counter_format(counter)
  local key = assert(Sobject { name = key_name })
  local mac_response = assert(key:mac { data = Blob.from_bytes(c), alg = hash_alg })
  local sign = { string.byte(mac_response.mac:bytes(), 1, 20) }
  local offset = 1 + sign[20] % 0x10
  local r = tostring(
    0x1000000 * (sign[offset] % 0x80) +
    0x10000 * (sign[offset + 1]) +
    0x100 * (sign[offset + 2]) +
    (sign[offset + 3])
  ):sub(-digits)
  if #r < digits then
    r = string.rep("0", digits - #r) .. r
  end
  return r
end

local function percent_encode_char(c)
  return string.format("%%%02X", c:byte())
end

local function url_encode(str)
  -- We use a temporary variable to discard the second result returned by gsub
  local r = str:gsub("[^a-zA-Z0-9.~_-]", percent_encode_char)
  return r
end

------ TOTP functions ------

local totpmt = {}

function otp.new_totp(account, key_length, digits, period, hash_alg)
  local r = {
    type = "totp",
    key_name = totp_name_prefix .. account,
    key_length = key_length or default_key_length,
    hash_alg = hash_alg or default_hash_algorithm,
    digits = digits or default_digits,
    period = period or default_period,
    counter = 0,
  }
  setmetatable(r, { __index = totpmt, __tostring = totpmt.metadata })
  return r
end

local function get_time(param)
  if type(param) == "string" then
    return Time.from_iso8601(param):unix_epoch_seconds()
  elseif type(param) == "number" then
    return param
  else
    return Time.now_insecure():unix_epoch_seconds()
  end
end

local function totp_generate_password(self, deviation, for_time)
  local counter = math.floor(get_time(for_time) / self.period) + (deviation or 0)
  return
    generate_password(self.key_name, counter, self.digits, self.hash_alg),
    counter
end

function totpmt:generate_password(deviation, for_time)
  local r = totp_generate_password(self, deviation, for_time)
  return r -- discard second value
end

function totpmt:verify(code, accepted_deviation, for_time)
  if #code ~= self.digits then return false end
  local ad = accepted_deviation or default_totp_deviation
  for d = -ad, ad do
    local verif_code, verif_counter = totp_generate_password(self, d, for_time)
    if verif_counter >= self.counter and code == verif_code then
      self.counter = verif_counter + 1
      return true
    end
  end
  return false
end

function totpmt:get_url(raw_key, issuer, account, issuer_uuid)
  local key, issuer, account = url_encode((basexx.to_base32(raw_key):gsub('=', ''))), url_encode(issuer), url_encode(account)
  local issuer_uuid = issuer_uuid and url_encode(issuer_uuid) or issuer
  return table.concat{
    "otpauth://totp/",
    issuer, ":", account,
    "?secret=", key,
    "&issuer=", issuer_uuid,
    "&period=", tostring(self.period),
    "&digits=", tostring(self.digits),
    "&algorithm=", self.hash_alg,
  }
end

function totpmt:metadata()
  local fields = {
    "totp",
    metadata_format_version,
    tostring(self.digits),
    tostring(self.period),
    tostring(self.counter),
    self.hash_alg,
  }
  return table.concat(fields, ":") .. ":"
end

function totpmt:store_in_dsm(account, must_create)
  if account == nil or type(account) ~= "string" then
    return nil, Error.new("expected a string for `account`")
  end
  local name = totp_name_prefix .. account
  -- First see if the object exists
  local hmac_key, err = Sobject { name = name }
  if err == nil and must_create == true then
    return nil, Error.new("a security object associated with this account already exists")
  end
  local url = nil
  if err ~= nil then
    raw_key = Blob.random { bytes = self.key_length }:bytes()
    url = self:get_url(raw_key, totp_issuer, account)
    hmac_key, err = Sobject.import {
      name = name,
      value = Blob.from_bytes(raw_key),
      obj_type = 'HMAC',
      key_ops = {"HIGHVOLUME", "MACGENERATE"},
    }
    if err ~= nil then
      return nil, Error.new("failed to import HMAC key: " .. tostring(err))
    end
  end
  -- Update the custom metadata with TOTP parameters
  _, err = hmac_key:update { custom_metadata = { totp_params = self:metadata() } }
  if err ~= nil then return nil, err end
  return {
    security_object = name,
    url = url, -- will only have a value if a key was created.
  }
end

function otp.get_totp_from_dsm(account)
  local name = totp_name_prefix .. account
  local hmac_key, err = Sobject { name = name }
  if err ~= nil then return nil, Error.new("could not find the security object associated with this account: " .. tostring(err)) end
  if hmac_key.obj_type ~= "HMAC" then
    return nil, Error.new("expected an HMAC key found `" .. hmac_key.obj_type .. "`")
  end
  if (not hmac_key.custom_metadata) or (not hmac_key.custom_metadata.totp_params) then
    return nil, Error.new("could not find custom metadata `totp_params` on the key")
  end

  local totp_params = hmac_key.custom_metadata.totp_params
  local items = {}
  for item in string.gmatch(totp_params, "([^:]*):") do
    items[#items + 1] = item
  end
  if #items < 6 or items[1] ~= "totp" or tonumber(items[2]) > metadata_format_version then
    return nil, Error.new("invalid custom metadata value for `totp_params`")
  end
  local version = tonumber(items[2])
  if version == 1 then
    local r = {
      type = "totp",
      key_name = name,
      key_length = hmac_key.key_size / 8,
      digits = tonumber(items[3]),
      period = tonumber(items[4]),
      counter = tonumber(items[5] or "0"),
      hash_alg = items[6],
    }
    setmetatable(r, { __index = totpmt })
    return r
  else
    return nil, Error.new("unsupported serialization format version")
  end
end

-------------------------------------------------------------

function table_foreach(tab, func)
  local res = {}
  for k, v in pairs(tab) do
    res[k] = func(k, v)
  end
  return res
end

function expect_input_field(obj, field_name, expected_type, expected_json_type)
  if not obj[field_name] then
    return nil, Error.new("missing required input field `" .. field_name .. "`")
  end
  if type(obj[field_name]) ~= expected_type then
    return nil, Error.new("invalid value for `" .. field_name .. "`, expected a " .. (expected_json_type or expected_type))
  end
  return obj[field_name]
end

function run(input)
  local operation, err = expect_input_field(input, "operation", "string")
  if err ~= nil then return nil, err end

  local account, err = expect_input_field(input, "account", "string")
  if err ~= nil then return nil, err end

  local op_generate = "generate"
  local op_verify = "verify"

  local all_ops = { op_generate, op_verify }

  if operation == op_generate then
    local totp = otp.new_totp(account)
    return totp:store_in_dsm(account, true) -- must_create
  end

  if operation == op_verify then
    local code, err = expect_input_field(input, "code", "string")
    if err ~= nil then return nil, err end

    local totp, err = otp.get_totp_from_dsm(account)
    if err ~= nil then return nil, err end
    local verified = totp:verify(code)
    totp:store_in_dsm(account, false) -- to ensure the same code cannot be used again
    return { verified = verified }
  end

  local all_ops_quoted = table_foreach(all_ops, function(k, v) return "'" .. v .. "'" end)
  return nil, Error.new("unknown operation '" .. operation .. "', expected one of the following: " .. table.concat(all_ops_quoted, ", "))
end
