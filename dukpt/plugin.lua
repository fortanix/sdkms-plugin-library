-- Name: DUKPT
-- Version: 1.0
-- Description:## Short Description
-- Plugin for importing DUKPT BDKs and for encrypting and decrypting data using the DUKPT procedure.
-- ### ## Introduction
-- DUKPT plugin is an SDKMS implementation of the Derived Unique Key Per Transaction process that's described in Annex A of ANS X9.24-2009. This module provides DUKPT decryption using the 3DES scheme. It decrypts the encrypted card information using the KSN and BDK-ID as inputs to the plugin and generates decrypted/plain card information.
-- 
-- Initially there is a Base Derivation Key (BDK) that is used to generate the "Initial PIN Encryption Key" (IPEK). The BDK always stays in the HSM and is never injected into the devices. It is known only by the manufacturer and the merchant. The "Key Serial Number" (KSN) and IPEK are injected into each device. The KSN is sent with the "crypt" material so that the receiving end can also decrypt it. The last 21 bits of the KSN are a counter that gets incremented every transaction.
-- 
-- There is a single DUKPT plugin, with three supported operations: `import`, `encrypt`, and `decrypt`.
-- 
-- ## Use Cases
-- As described above in the Introduction, the value of DUKPT is the ability to secure many independent messages in such a way that compromising the keys for any individual message doesn't endanger other messages while still minimizing the number of keys that need to be stored and managed. The canonical example of
-- this, and the use case for which this procedure was developed, is to encrypt payment information during transactions.
-- 
-- ## Setup
-- ### Using SDKMS Plugins
-- * Plugins are an independent and secure subsystem where business logic can be
--   executed inside SDKMS.
-- * Plugins are invoked using a REST API similar to the cryptographic and key
--   management APIs.
-- * Plugins are identified by UUID, like apps and security objects.
-- * To invoke a plugin, make a POST request to `https://<API endpoint>/sys/v1/plugins/<uuid>`.
--   The POST request body must be either valid
--   JSON or empty. The exact structure is defined by the plugin.
-- * The request may return:
--     - 200 OK with a JSON response body,
--     - 204 No Content with empty response body, or
--     - a 4xx/5xx error with a plain text error message response body.
-- 
-- ### Invoking SDKMS plugins from SDKMS Python CLI
-- Check the SDKMS CLI README for information on setting up the CLI.
-- 
-- Login to sdkms inorder to invoke plugin:
-- 
-- `$ sdkms-cli user-login`
-- 
-- To invoke a plugin:
-- 
-- `$ sdkms-cli invoke-plugin --name dukpt --in <decrypt-in.json>`
-- 
-- * Plugins can either be invoked using `--name` or `--id`, taking the plugin's name or UUID respectively.
-- * `in` : Path to input json file.
-- 
-- ## DUKPT Input/Output JSON Formats
-- The following sections specify the fields in the inputs and outputs of the plugin's operations, which are JSON maps.
-- 
-- ### DUKPT Import Operation
-- #### Input
-- * `operation` : Must be the string `import` for importing BDKs.
-- * `name` : A string to be used as the name of the key in SDKMS. Must be unique.
-- * `material` : A string containing the 16 hex encoded bytes of the key material.
-- 
-- #### Output
-- * `key_id` : The UUID of the imported key in SDKMS. Referred to in the other
--   operations as `bdk_id`.
-- 
-- ### DUKPT Encrypt and Decrypt
-- #### Input
-- * `operation` : Either `encrypt` or `decrypt`, for encryption and decryption
--   respectively.
-- * `bdk_id` : The UUID of the imported BDK key to use.
-- * `ksn` : Key serial number, hex encoded.
-- * `key_mode` : The method used for deriving the session key from the IPEK.
--   Possible values are:
--     - `datakey`
--     - `pinkey`
--     - `mackey`
-- * `card_data` : The data to be encrypted or decrypted, encoded in a string in accordance with the encoding specified below.
-- * `encoding` : For the `encrypt` operation this is the encoding of the data to be encrypted. For `decrypt`, this is the encoding that the data should be returned in.
--   Possible values are:
--     - `base64`
--     - `hex`
-- 
-- #### Output
-- * `card_data` : The result of the encryption or decryption.
-- 
-- ## Example Usages
-- ### DUKPT Import
-- Imports a BDK into SDKMS for use with the other operations.
-- 
-- #### Example Input
-- ```json
--     { "operation": "import",
--       "name": "my_bdk",
--       "material": "0123456789ABCDEFFEDCBA9876543210" }
-- ```
-- 
-- #### Example Output
-- ```json
--     { "key_id": "d17e7c0c-3246-41c4-9824-c98d2c6515fb" }
-- ```
-- 
-- ### DUKPT Encrypt and Decrypt
-- Encrypts or decrypts data with a key derived from the given BDK and KSN.
-- 
-- #### Example Input
-- Below is a sample input json to the SDKMS DUKPT plugin's decrypt operation. The
-- structure is the same for encryption, though the semantics change slightly as
-- described above.
-- ```json
--     { "operation": "decrypt",
--       "bdk_id": "fd1fbe76-6d64-4d30-b351-e79449e1eb77",
--       "ksn": "FFFF9876543210E00008",
--       "key_mode": "datakey",
--       "card_data": "y07Fue/gKW7x9yDM06LZBg==",
--       "encoding": "base64" }
-- ```
-- 
-- #### Example Output
-- ```json
--     { "card_data": "Zm9ydGFuaXg=" }
-- ```
-- 
-- ## References
-- 
-- * [https://github.com/dpjayasekara/node-dukpt](https://github.com/dpjayasekara/node-dukpt "NodeJS DUKPT implementation")
-- * [https://github.com/sgbj/Dukpt.NET](https://github.com/sgbj/Dukpt.NET "C# DUKPT implementation")
-- * [https://support.fortanix.com/sdkms/developers-guide-plugin.html](https://support.fortanix.com/sdkms/developers-guide-plugin.html "SDKMS developers guide plugin")
-- * [https://support.fortanix.com/api/#/Plugins](https://support.fortanix.com/api/#/Plugins "SDKMS plugins API")
-- 
-- ### Release Notes
-- - Initial Release

-- EDE3 method to covert 16-byte key to 24-byte
-----------------------------------------
-- Copy first 8 bytes of the key and append to end of the key
-- @param key
-----------------------------------------
function ede3KeyExpand(key)
    local firstHalf = string.sub(key, 1, #key / 2)
    return key .. firstHalf
end

-- import a key from value using Sobject import
------------------------------------------------
-- @param algo as string - DES3
-- @param value key's value as Blob
-- @param size size of the key
------------------------------------------------
function importKey(algo, value, size, name)
    local value = Blob.from_hex(value)
    local res,err = Sobject.import {
        obj_type = algo,
        value = value,
        key_size = size,
        name = name
    }
    assert(res, 'Error importing key : ' .. tostring(err))
    return res
end

-- import a key from value using Sobject import
------------------------------------------------
-- @param algo as string - DES, DES3
-- @param value key's value as Blob
-- @param size size of the key
-- @param transient as boolean
------------------------------------------------
function importTransientKey(algo, value, size)
    local res, err = Sobject.import {
        obj_type = algo,
        value = value,
        key_size = size,
        transient = true
    }
    assert(res, 'Error importing key : ' .. tostring(err))
    return res
end

-- get the bdk Blob from bdk_key_id
----------------------------------------
-- @param bdk_key_id
function getBdk(bdk_key_id)
    local key = Sobject {kid = bdk_key_id}
    return extractKey(key)
end

-- Extracts the key value using sdkms
-----------------------------------------
-- @param key to be extracted
-----------------------------------------
function extractKey(key)
    local res, err = key:export {}
    assert(res, 'Error extracting key : ' .. tostring(err))
    return res.value
end

-- Generates the IPEK in Hex Format from given BDK and KSN
-----------------------------------------
-- @param bdk 16 byte BDK in HEX format
-- @param ksn in hex format
-----------------------------------------
function generateIPEK(bdk, ksn)
    local key = bdk

    -- masking 10 byte initial KSN by AND operation with hex value 0xFFFFFFFFFFFFFFE00000
    local maskedKSN = Blob.from_hex('FFFFFFFFFFFFFFE00000', 16) & Blob.from_hex(ksn, 16)

    -- abstract the left most 8 bytes from masked KSN
    maskedKSN = string.sub(maskedKSN:bytes(), 1, 8)
    maskedKSN = Blob.from_bytes(maskedKSN)

    local ipek_left_half = encrypt(importTransientKey('DES3', key, 168), maskedKSN, 'CBCNOPAD', '\0\0\0\0\0\0\0\0')

    -- Now get the right half of IPEK
    local mask = 'C0C0C0C000000000C0C0C0C000000000'
    key = Blob.from_hex(mask) ~ Blob.from_hex(string.sub(bdk:hex(), 1, 32))
    key = ede3KeyExpand(key:bytes())
    key = Blob.from_bytes(key)

    local ipek_right_half = encrypt(importTransientKey('DES3', key, 168), maskedKSN, 'CBCNOPAD', '\0\0\0\0\0\0\0\0')

    -- merge the right and left half to create the IPEK
    local ipek = ipek_left_half.cipher .. ipek_right_half.cipher

    return ipek
end

--- Returns HEX representation of a number
-----------------------------------------
-- @param num number to be converted to hex string
function numToHex(num)
    local hexstr = '0123456789abcdef'
    local s = ''
    while num > 0 do
        local mod = math.fmod(num, 16)
        s = string.sub(hexstr, mod + 1, mod + 1) .. s
        num = math.floor(num / 16)
    end
    if s == '' then
        s = '0'
    end
    return s
end

-- Returns the counter value in integer from
-- KSN by ANDing its bottom three bytes with 0x1FFFFF.
----------------------------------------
-- @param ksn_blob original 10 byte ksn
----------------------------------------
function getCounter(ksn_blob)
    local ksn_bytes = ksn_blob:bytes()
    local tail_three_bytes = string.sub(ksn_bytes, -3, -1)
    local counter_blob = Blob.from_bytes(tail_three_bytes) & Blob.from_hex('1FFFFF', 16)
    return tonumber(counter_blob:hex(), 16)
end

-----------------------------------------
-- @param key_blob key in blob format
-- @param reg_blob ksn in Blob format
function encryptRegister(key_blob, reg_blob)
    local bottom8 = Blob.from_bytes(string.sub(key_blob:bytes(), -8, -1))
    local top8 = Blob.from_bytes(string.sub(key_blob:bytes(), 1, 8))
    local bottom8xorKSN = bottom8 ~ reg_blob

    local desEncrypted = encrypt(importTransientKey('DES', top8, 56), bottom8xorKSN, 'CBCNOPAD', '\0\0\0\0\0\0\0\0')
    return bottom8 ~ desEncrypted.cipher
end

-- generate the key
-----------------------------------------
-- Return the generated key in Blob format
-- @param key_blob key in Blob format
-- @param ksn_blob ksn in Blob format
-----------------------------------------
function generateKey(key_blob, ksn_blob)
    local mask = 'C0C0C0C000000000C0C0C0C000000000'
    local maskedKey = Blob.from_hex(mask) ~ key_blob
    local left = encryptRegister(maskedKey, ksn_blob)
    local right = encryptRegister(key_blob, ksn_blob)

    return left .. right
end

-- Derives base key in Blob format
-----------------------------------------
-- @param ipek_blob ipek in Blob format
-- @param ksn_blob ksn in Blob format
-----------------------------------------
function deriveKey(ipek_blob, ksn_blob)
    local ksn = ksn_blob
    local ksn_bytes = ksn:bytes()
    if #ksn_bytes == 10 then
        ksn = string.sub(ksn_bytes, -8, -1)
        ksn = Blob.from_bytes(ksn)
    end

    local baseKSN = ksn & Blob.from_hex('FFFFFFFFFFE00000')
    local curKey = ipek_blob
    local counter = getCounter(ksn_blob)
    local shiftReg = tonumber('100000', 16)

    while shiftReg > 0 do
        if (shiftReg & counter) > 0 then
            local baseKsnOR = tonumber(Blob.from_bytes(string.sub(baseKSN:bytes(), -3, -1)):hex(), 16) | shiftReg
            baseKSN = Blob.from_bytes(string.sub(baseKSN:bytes(), 1, 5)) .. Blob.from_hex(numToHex(baseKsnOR))
            curKey = generateKey(curKey, baseKSN)
        end
        shiftReg = shiftReg >> 1
    end
    return curKey
end

-- If the key mode is 'mackey' then use
-- this function to generate data key
-----------------------------------------
-- Returns the session key (of type mackey) in hex format
-- @param ipek ipek Blob
-- @param ksn ksn Blob
-----------------------------------------
function createMACKey(ipek, ksn)
    local derived_PEK = deriveKey(ipek, ksn)
    local variant_mask = '000000000000FF00000000000000FF00' -- MAC variant
    local masked_PEK = Blob.from_hex(variant_mask) ~ derived_PEK
    return masked_PEK:hex()
end

-- If the key mode is 'pinkey' then use
-- this function to generate data key
-----------------------------------------
-- Returns the session key (of type pinkey) in hex format
-- @param ipek ipek Blob
-- @param ksn ksn Blob
-----------------------------------------
function createPINKey(ipek, ksn)
    local derived_PEK = deriveKey(ipek, ksn)
    local variant_mask = '00000000000000FF00000000000000FF' -- PIN variant
    local masked_PEK = Blob.from_hex(variant_mask) ~ derived_PEK
    return masked_PEK:hex()
end

-- If the key mode is 'datakey' then use
-- this function to generate data key
-----------------------------------------
-- Returns the session key (of type datakey) in hex format
-- @param ipek ipek Blob
-- @param ksn ksn Blob
-----------------------------------------
function createDataKey(ipek, ksn)
    local derived_PEK = deriveKey(ipek, ksn)
    local variant_mask = '0000000000FF00000000000000FF0000' -- data variant

    local masked_PEK = Blob.from_hex(variant_mask) ~ derived_PEK

    local expanded_masked_PEK = Blob.from_bytes(ede3KeyExpand(masked_PEK:bytes()))

    -- left half
    local session_key_left = encrypt(importTransientKey('DES3', expanded_masked_PEK, 168), Blob.from_bytes(string.sub(masked_PEK:bytes(), 1, 8)), 'CBCNOPAD', '\0\0\0\0\0\0\0\0')

    -- right half
    local session_key_right = encrypt(importTransientKey('DES3', expanded_masked_PEK, 168), Blob.from_bytes(string.sub(masked_PEK:bytes(), -8, -1)), 'CBCNOPAD', '\0\0\0\0\0\0\0\0')

    local session_key = session_key_left.cipher .. session_key_right.cipher

    return session_key:hex()
end

-- Derives the session key based on mode
-----------------------------------------
-- Returns the session key in hex format
-- @param ipek Blob
-- @param ksn_hex ksn in hex format
-- @param key_mode datakey, pinkey or mackey
function deriveSessionKey(ipek, ksn_hex, key_mode)
    local ksn = Blob.from_hex(ksn_hex)
    if key_mode == 'datakey' then
        return createDataKey(ipek, ksn)
    elseif key_mode == 'pinkey' then
        return createPINKey(ipek, ksn)
    elseif key_mode == 'mackey' then
        return createMACKey(ipek, ksn)
    end
end

-- Encrypts the message based on given parameter values
-----------------------------------------
-- @param message message to be encrypted as Blob
-- @param algo as string - DES, DES3
-- @param mode as string - CBC, CBCNOPAD
-- @param iv as string
-----------------------------------------
function encrypt(key, message, mode, iv)
    local res, err = key:encrypt {
        plain = message,
        mode = mode,
        iv = Blob.from_bytes(iv)
    }
    assert(res, 'Error encrypting data : ' .. tostring(err))
    return res
end

-- Encrypts the plain card data
-------------------------------------------------------
-- Returns the encrypted output in base64 encoded format
-- @param session_key in hex format
-- @param plain_data in base64 encoded form
-- @param input_encoding in string
function dukptEncrypt(session_key, plain_data, input_encoding)
    plain_data = decode(plain_data, input_encoding)
    local key_bytes = ede3KeyExpand(session_key)
    key_bytes = Blob.from_hex(key_bytes)
    local key = importTransientKey('DES3', key_bytes, 168)
    plain_data = pad(plain_data)
    local encrypted_output = encrypt(key, plain_data, 'CBCNOPAD', '\0\0\0\0\0\0\0\0')

    return {
        card_data = encrypted_output.cipher
    }
end

-- Decrypts the cipher based on given parameter values
-----------------------------------------
-- @param cipher cipher to be decrypted as Blob
-- @param key is data encryption key
-- @param mode as string - CBC, CBCNOPAD
-- @param iv as string
-----------------------------------------
function decrypt(key, cipher, mode, iv)
    local res, err = key:decrypt {
        cipher = cipher,
        mode = mode,
        iv = Blob.from_bytes(iv)
    }
    assert(res, 'Error decrypting data : ' .. tostring(err))
    return res
end

-- Decrypts the encrypted card data
--------------------------------------------------------
-- Returns the decrypted output in base64 encoded format
-- @param session_key in hex format
-- @param encrypted_data in base64 encoded form
-- @param output_encoding in string
function dukptDecrypt(session_key, encrypted_data, output_encoding)
    local key_bytes = ede3KeyExpand(session_key)
    local decrypted_output = decrypt(importTransientKey('DES3', Blob.from_hex(key_bytes), 168), Blob.from_base64(encrypted_data), 'CBCNOPAD', '\0\0\0\0\0\0\0\0')
    decrypted_output = unpad(decrypted_output.plain)
    decrypted_output = encode(decrypted_output, output_encoding)
    return {
        card_data = decrypted_output
    }
end

-- Handle padding for input data
------------------------------------------------
-- Returns the padded input
-- @param plain_data in form of bytes
function pad(plain_data)
    local plain_data_lenth = #plain_data:bytes()
    local pad_length = plain_data_lenth % 8
    local pad_bytes = Blob.from_bytes('')
    if pad_length > 0 then
        pad_length = 8 - pad_length
        while pad_length > 0 do
            pad_bytes = pad_bytes .. Blob.from_bytes('\0')
            pad_length = pad_length - 1
        end
    end
    plain_data = plain_data .. pad_bytes
    return plain_data
end

-- Handle padding for output
------------------------------------------------
-- Returns the unpadded decrypted output
-- @param decrypted_ouput in base64 encoded form
function unpad(decrypted_output)
    local decrypred_bytes = decrypted_output:bytes()
    local len = #decrypred_bytes
    local i = 1
    local char = string.byte(string.sub(decrypred_bytes, len, len))
    while char == string.byte('\0') do
        char = string.byte(string.sub(decrypred_bytes, len - i, len - i))
        i = i + 1
    end
    i = i - 1
    return Blob.from_bytes(string.sub(decrypted_output:bytes(), 1, len - i))
end

-- Convert the specified encoding format to bytes
---------------------------------------------------
-- Returns the plain data in bytes
-- @param plain_data in base64 encoded form
-- @param input_encoding in string
function decode(data, encoding)
    if encoding:lower() == 'hex' then
        return Blob.from_hex(data)
    end
    return Blob.from_base64(data)
end

-- Convert bytes to the required encoding format
---------------------------------------------------
-- Returns the bytes in specified format
-- @param decrypted_output in base64 encoded form
-- @param output_encoding in string
function encode(data, encoding)
    if encoding:lower() == 'hex' then
        return data:hex()
    end
    return data
end

-- Validates input for required fields
------------------------------------------------------
-- Returns the error if any mandatory field is missing
-- @param input to plugin
function validate(input)
    if input.operation == nil then
        return Error.new {
            status = 400,
            message = 'Missing required input parameter operation'
        }
    end
    if not (input.operation == 'import' or
            input.operation == 'encrypt' or
            input.operation == 'decrypt' ) then
        return Error.new {
            status = 400,
            message = 'Invalid operation, must be either import, encrypt, or decrypt'
        }
    end
    if input.operation == 'import' then
        if input.material == nil then
            return Error.new {
                status = 400,
                message = 'Missing required input parameter bdk_material'
            }
        end
        if input.name == nil then
            return Error.new {
                status = 400,
                message = 'Missing required input parameter name'
            }
        end
        if #input.material ~= 32 then
            return Error.new {
                status = 400,
                message = 'Bdk length is invalid. Expected input length is 16 bytes'
            }
        end
    else
        -- Encrypt or Decrypt
        -- Assign default values
        if input.encoding == nil then
            input.encoding = 'base64'
        end

        if not (input.encoding:lower() == 'hex' or
                input.encoding:lower() == 'base64') then
            return Error.new {
                status = 400,
                message = 'Invalid encoding requested. Supported types are hex or base64'
            }
        end
        if input.bdk_id == nil then
            return Error.new {
                status = 400,
                message = 'Missing required input parameter bdk_id'
            }
        end
        if input.ksn == nil then
            return Error.new {
                status = 400,
                message = 'Missing required input parameter ksn'
            }
        end
        if input.key_mode == nil then
            return Error.new {
                status = 400,
                message = 'Missing required input parameter key_mode'
            }
        end
        local key = Sobject {kid = input.bdk_id}
        if key == nil then
            return Error.new {
                status = 400,
                message = 'Bdk does not exist in sdkms. Please verify input'
            }
        end
        if input.card_data == nil then
            return Error.new {
                status = 400,
                message = 'Missing required input parameter card_data'
            }
        end
    end
end

-- There are 2 valid structures for input
-- For imports: {
--     "operation": "import",
--     "material": <16 byte hex encoded key>,
--     "name": <name>
-- }
-- For encryption and decryption: {
--     "operation": <"encrypt" or "decrypt">,
--     "bdk_id": <bdk uuid in sdkms>,
--     "key_mode": <datakey, mackey, or pinkey>,
--     "card_data": <card data>,
--     "encoding": <hex or base64>
-- }
-- When the operation is encryption, the encoding specifies how the input data
-- is encoded. When the operation is decryption, the encoding specifies how the
-- output data should be encoded.
function run(input)
    -- Validate mandatory fields in the request
    local error = validate(input)
    if error ~= nil then
        return error
    end

    if input.operation == 'import' then
        -- Expand material to expand to 24 bytes to import to sdkms
        local key_material = ede3KeyExpand(input.material)

        local key_object = importKey('DES3', key_material, 168, input.name)

        return {
            key_id = key_object.kid
        }
    end
    --Extract bdk
    local bdk_value = getBdk(input.bdk_id)

    --Generate IPEK
    local ipek = generateIPEK(bdk_value, input.ksn)

    --Derive Session key
    local session_key = deriveSessionKey(ipek, input.ksn, input.key_mode)
    if input.operation == 'encrypt' then
        --Perform dukpt encrypt
        return dukptEncrypt(session_key, input.card_data, input.encoding)
    elseif input.operation == 'decrypt' then
        --Perform dukpt decrypt
        return dukptDecrypt(session_key, input.card_data, input.encoding)
    end
end

