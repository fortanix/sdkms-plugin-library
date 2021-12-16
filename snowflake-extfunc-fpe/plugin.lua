-- Name: Snowflake External Function for FPE Tokenization
-- Version: 1.0
-- Description:## Short Description
-- Uses AES keys with FF1 algorithm in Fortanix DSM to protect sensitive fields in Snowflake.
--
-- ### ## Introduction
-- Snowflake data proection implemented through a DSM Plugin executing inside Fortanix Data Security Manager.
--
-- ## Use Cases
--
-- Snowflake users authorized to invoke an External Function, can encrypt/tokenize or decrypt/detokenize 
-- individual fields or one or more columns. 
--
-- ## Setup
--
-- ### Create the DSM Plugin, FPE Tokenization Keys, and at least one DSM App
--
-- Import this Plugin from the Fortanix Plugin Library. Setup the necessary tokenization key(s).
-- For example, a tokenization key with SSN format to tokenzie social security number fields.
-- You can create as many keys as necessary to tokenize or encrypt desired fields.
--
-- Note: Each Tokenization Key must correspond to a single data type (or column) in Snowflake.
-- Unless there's a generic Tokenization Key that accepts an arbitrary data format in a chosen
-- character encoding.
--
-- Ensure the Plugin and Tokenization Key(s) are members of the same DSM Group.
--
-- Create a DSM App and note its API key as `FORTANIX_DSM_API_KEY`. 
-- For each Snowflake External Function, a corresponding DSM App can be specified during its creation in Snowflake.
-- The DSM App(s) will need permissions to either `encrypt`, `decrypt`, or `masked decrypt` using the FPE keys in DSM.
--
--
-- Copy or note the newly created Plugin's URL from DSM. It will be in the following format:
--
-- ```
-- https://FORTANIX_DSM_ENDPOINT/sys/v1/plugins/PLUGIN_UUID
-- ```
--
-- ### Create the AWS API Gateway proxy
--
-- AWS API Gateway REST API Endpoints may be public or private. You will need two separate resources
-- for /tokenize and /detokenize, that match separate distinct External Functions in Snowflake. Both these
-- endpoints could invoke the same DSM Plugin, since we will map the headers from Snowflake to request body
-- parameters that inform the DSM Plugin of `encrypt` or `decrypt`.
--
-- Use the following configurations for each resource:
--
--
-- - Integration type: HTTP
-- - Endpoint URL:  `https://FORTANIX_DSM_ENDPOINT/sys/v1/plugins/PLUGIN_UUID`
-- - Content handling: Passthrough
-- - HTTP Headers: add the “Authorization” header and leave the value empty as it’ll be mapped from the Snowflake custom header.
--
-- Mapping Template:
-- -  Content-Type: “application/json”
-- -  Request body passthrough: “Never”
-- -  Value: see below
--
-- ```
-- set($apikey = "Basic $input.params('sf-custom-api-key')")
-- set($context.requestOverride.header.Authorization = $apikey)
-- set($context.requestOverride.header.sf-custom-api-key = "")
-- set($context.requestOverride.header.sf-custom-key-names = "")
-- set($inputRoot = $input.path('$'))
-- {
-- "op": "encrypt",
-- "keys":"$input.params('sf-custom-key-names')",
-- "data": $input.json('$.data')
-- }
-- ```
--
-- Note: change the `op` from `encrypt` to `decrypt` based on the REST API endpoint.
--
-- Optional: Test the API Gateway resource and deploy to a stage with the following:
--
-- Resource: /tokenize
-- Query string: empty or leave blank
-- Headers:
--
-- ```
-- Accept:application/json
-- sf-custom-api-key:FORTANIX_DSM_API_KEY
-- sf-custom-key-names:Case-Sensitive,Comma-Separated,List-of-Key,Names...
-- ```
--
-- Request Body:
-- ```json
-- {"data": [
--     [0, "Susan"],
--     [1, "Sean"],
--     [2, "Samual"],
--     [3, "Hollee"]
--]}
--```
--
-- Note: the number of columns need to match the number of key names. The FPE key in this example needs to 
-- finalize the AWS API Gateway integration by:
--
-- Creating an AWS IAM Role and note its `SNOWFLAKE-ROLE-ID` and deploy the proxy to a stage and note the URL:
--
-- ```
-- https://<<XYZ.execute-api.us-east-2>>.amazonaws.com/DEMO_STAGE/
--
-- ```
--
-- ### Create the Snowflake API Integration and External Function
--
-- Configure the AWS Gateway API Integration deployment stage and IAM Role in Snowflake.
--
-- ```
-- CREATE OR REPLACE API INTEGRATION fortanix_plugin
--   API_PROVIDER = aws_api_gateway
--   API_AWS_ROLE_ARN = 'arn:aws:iam::ACCOUNT_ID:role/service-role/SNOWFLAKE-ROLE-ID'
--  API_ALLOWED_PREFIXES = ('https://<<XYZ.execute-api.us-east-2>>.amazonaws.com/DEMO_STAGE/')
--   enabled=true;
--
-- DESCRIBE INTEGRATION fortanix_plugin;
-- ```
--
-- Note: replace the ACCOUNT_ID and other relevant parameters with appropriate values in the API INTEGRATION statement.
--
-- Create External Functions for single columns, say corresponding to SSN. Similar functions can be setup
-- for other data types or multiple columns within a single External Function.
--
-- ```
-- Single column tokenization: SSN
-- DROP FUNCTION dsm_tokenize_ssn(varchar);
-- 
-- CREATE SECURE EXTERNAL FUNCTION dsm_tokenize_ssn(SSN_column_name varchar)
--   RETURNS variant
--   IMMUTABLE
--   API_INTEGRATION = fortanix_plugin
--   HEADERS = (
--       'api-key'='FORTANIX_DSM_API_KEY',
--       'key-names'='SSN_FPE_key_name_in_DSM'
--   )
--   AS 'https://<<XYZ.execute-api.us-east2>>.amazonaws.com/DEMO_STAGE/tokenize';
--
-- select dsm_tokenize_ssn('123-45-6789');
--
-- Single column detokenization: SSN
-- DROP FUNCTION dsm_detokenize_ssn(varchar);
--
-- CREATE EXTERNAL SECURE FUNCTION dsm_detokenize_ssn(SSN_column_name varchar)
--   RETURNS variant
--   IMMUTABLE
--   API_INTEGRATION = fortanix_plugin
--   HEADERS = (
--      'api-key'='FORTANIX_DSM_API_KEY',
--      'key-names'='SSN_FPE_key_name_in_DSM'
-- )
--
-- AS 'https://<<XYZ.execute-api.us-east-2>>.amazonaws.com/DEMO_STAGE/detokenize';
--
-- select dsm_detokenize_ssn('806-30-1382');
--
-- ```
--
-- Setup a test table and test the function against it:
--
-- ```
-- CREATE or REPLACE TABLE test_table (
--      id number autoincrement start 1 increment 1,
--      fname varchar,
--      ssn varchar,
--      addr varchar,
--      ccn varchar
-- );
--
-- test SSN tokens
-- insert into test_table (id, fname, ssn, addr, ccn) select 1, 'Franky Hou', 
--     dsm_tokenize_ssn('001-02-0001')[0]::text, '1 Infinity Loop', dsm_tokenize_ccn('1234123412341234')[0]::text;
-- insert into test_table (id, fname, ssn, addr, ccn) select 2, 'Joan Lucas',
--     dsm_tokenize_ssn('001-02-0002')[0]::text, '918 Batman Drive', dsm_tokenize_ccn('9876987698769876')[0]::text;
-- insert into test_table (id, fname, ssn, addr, ccn) select 3, 'James Woods',
--     dsm_tokenize_ssn('001-02-0003')[0]::text, '482 Woody Ave', dsm_tokenize_ccn('1849372849384723')[0]::text;
--
-- test SSN PII re-identification
-- select ssn, dsm_detokenize_ssn(ssn)[0]::text from test_table;
--
-- ```
--
-- Note: the DSM App needs to have permissions to detokenize using the SSN tokenization key, which
-- itself needs to have the permissions. Fortanix DSM allows for a very flexible RBAC model on keys, and apps.
--
-- ## Example Usage
--
-- Each External Function signature must match the number of keys and columns or fields sent to the DSM Plugin.
-- The key names must match exactly as the input, as DSM allows creation of case sensitive key names or labels.
--
-- Invoking the DSM plugin from a command line:
-- ```
-- $ curl -H "Authorization: Basic $FORTANIX_DSM_API_KEY" \
--    $FORTANIX_DSM_ENDPOINT/sys/v1/plugins/$PLUGIN_UUID \
--    -d @input_examples.json # see below
-- ```
--
-- Input example 1:
-- ```json
-- {
--   "op": "encrypt",
--   "keys": "AlphaNum,SSN-key,CCN-key",
--   "data": [
--     [0, "SUSAN", "001-11-0010", "4539943689232943"],
--     [1, "SEAN", "616-21-0666", "349915113632714"],
--    [2, "SAMUEL", "300-31-1930", "5929662954927004"],
--     [3, "HOLEE", "021-31-0930", "4929662954927007"]
--     ]
-- }
-- ```
--
-- Input example 2:
-- ```json
-- {
--   "op": "encrypt",
--   "keys": "Name_X,SSN_X,Address_X,Numeric,email-sizer,CCN_X",
--  "data": [
--     [
--       0,
--       "Karna Ugarte",
--       "171-73-7920",
--       "#57 Lester Road",
--       "28510",
--       "ugarte_57@siriusxm.com",
--       4716407329495455
--    ],[
--       1,
--       "Matty Grand Jr.",
--       "544-10-0225",
--       "14 N-Williams Street",
--       "26259",
--       "grand_15@datawire.net",
--       5414779952385357
--     ]
--   ]
-- }
-- ```
--
-- ### End-to-end Test
-- Execute SQL statements in the Snowflake console or through other Snowflake ODBC queries using
-- the newly created External Functions. Verify the tokenization and de-tokenization in Fortanix DSM.
--
--
-- ### Known Issues
-- * If Snowflake sends a cell (field value) in a floating point format, due to an internal LUA
-- limitation in Fortanix DSM, the string equivalent only captures the integral part (digits before
-- the decimal). The fractional part is not sent as input to the FPE algorithm.
--
-- ## References
-- - <a name="externalfunction"></a> [External Functions] (https://docs.snowflake.com/en/sql-reference/external-functions.html)
-- - <a name="gide"></a> [Using DSM With Snowflake] (https://support.fortanix.com/hc/en-us/articles/4407049792148-Using-Data-Security-Manager-with-Snowflake)
--
--
--
-- ### Release Notes
-- - Initial release

local cached_keys = {}

local level_info = 'INFO'
local level_warning = 'WARNING'
local level_error = 'ERROR'
local level_critical = 'CRITICAL'

function log_event(level, msg)
  local message = this_plugin().name .. ": " .. msg
  AuditLog.log { message = message, severity = level }
  return message
end

function check(input)
  if not input.data or type(input.data) ~= "table" then
    return nil, Error.new { status = 400, message = log_event(level_critical, "missing `data` field in input") }
  end

  if not input.keys or type(input.keys) ~= "string" or input.keys == "" then
    return nil, Error.new { status = 400, message = log_event(level_critical, "Missing keys input") }
  end
  for key_name in string.gmatch(input.keys, '([^,]+)') do
    local key = Sobject { name = key_name }
    if key == nil then
      return nil, Error.new { status = 400, message = log_event(level_critical, 'key named `'.. key_name .. '` was not found') }
    end
    table.insert(cached_keys, key)
  end
end

function run(input)
  local output = {}
  if input.debug then log_event(level_info, "Parsing input data") end
  local row_quartiles = {}
  if input.debug then
    row_quartiles[math.floor(#input.data/4)] = true
    row_quartiles[math.floor(#input.data/2)] = true
    row_quartiles[math.floor(#input.data*3/4)] = true
  end

  for row, values in ipairs(input.data) do
    local tokens = {}
    if input.debug and row_quartiles[row] then log_event(level_info, "Processing row: " .. row) end
    for col, pii in ipairs(values) do
      if col == 1 then goto skip_row_index end

      local key = cached_keys[col-1]
      if key == nil then
        return nil, Error.new { status = 400, message = log_event(level_error, 'Number of keys (' .. #cached_keys .. ') does not match number of fields ' .. #values .. ' in row ' .. row) }
      end

      local pii_str = tostring(pii)
      if math.type(pii) == "float" then
        pii_str = string.gsub(string.format("%.9f", pii), "[0]+$", "")
        if tonumber(pii_str) ~= pii then
          return nil, Error.new { status = 501, message = 
            log_event(level_warning, "Known issue noted in README") }
        end
      end
      if input.op == "decrypt" then
        op, err = key:decrypt { cipher = Blob.from_bytes(pii_str), mode = 'FPE' }
      else
        op, err = key:encrypt { plain = Blob.from_bytes(pii_str), mode = 'FPE' }
      end
      if err then
        return nil, Error.new { status = 400, message = log_event(level_error, 'Failed to ' .. input.op .. ': ' .. tostring(err)) }
      end
      
      local dtype = type(pii)
      if op and op.cipher then
        if dtype == "number" then
          table.insert(tokens, tonumber(op.cipher:bytes()))
        else
          table.insert(tokens, op.cipher:bytes())
        end
      elseif op and op.plain then
        if dtype == "number" then
          table.insert(tokens, tonumber(op.plain:bytes()))
        else
          table.insert(tokens, op.plain:bytes())
        end
      else
        if input.debug then log_event(level_info, "Unknown error during " .. input.op) end
      end
      ::skip_row_index::
    end
    table.insert(output, { row - 1, tokens })
  end
  if input.debug then log_event(level_info, "Complete") end
  return { data = output }
end
