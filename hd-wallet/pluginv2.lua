-- Name: HD Wallet
-- Version: 2.1
-- Description:## Short Description
-- This plugin implements hierarchical deterministic wallets (or "HD Wallets") BIP0032 protocol.
--  
-- ### ## Introduction
-- The plugin allows to derive child key (xprv, xpub) from a master key in a deterministic way, and/or sign transaction hashes for UTXO and ethereum type crypto coin.
-- 
-- ## Use cases
-- The plugin can be used to
-- 
-- - Derive child key for UTXO
-- - Derive child key for ethereum
-- - Derive child key for XRP
--
-- - Sign transaction for UTXO
-- - Sign transaction for ethereum
-- - Sign transaction for XRP
-- 
-- ## Setup
-- - Generate HD-Wallets master key manually
-- **Example Master Key:** `xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U` 
-- - Import master key in SDKMS as secret raw key
-- 
-- ## Input/Output JSON object format
-- 
-- **Input**
-- 
-- ```
-- {
--     "master_key_id": "<Master-Key-UUID>",
--     "path": "<Child-Key-Path>"  ,
--     "msg_hash": "<32-Byte-Message-Hash>",
--     "coin": "<Coin-Type>"
-- }
-- ```
-- 
-- **Output**
-- 
-- ```
--  "xprv": "<HD-Wallet-Private-Key>",
--  "xpub": "<HD-Wallet-Public-Key>",
--  "coin_signature": "<Bitcoin-canonicalized-ECDSA-signature>",
--  "signature": "<ECDSA signature>"
-- ```
-- 
-- * `master_key_id`: UUID of master key imported in SDKMS
-- * `path`: Path of key to be derived to sign e.g: m/0, m/1, m/2/10 etc
-- * `msg_hash`: 32 byte SHA-3 message hash
-- * `coin`: coin type utxo or eth
-- * `xprv`: BIP0032 private key
-- * `xpub`: BIP0032 public key
-- * `coin_signature`: Bitcoin canonicalized ECDSA signature
-- * `signature`: ECDSA signature
-- 
-- ## Example Input/Output JSON object for UTXO COIN (BTC, LTC, BCH, etc.)
-- **Input JSON object**
-- 
-- ```
-- {
--    "master_key_id": "0eae8ff0-553e-4f47-bb64-7c87f34bf5e5",
--    "coin": "utxo",
--    "path": "m/2",
--    "msg_hash": "45a0ee821b05400f513891bbb567a99139f3df72e9e1d4b48186841cc5996d2f"
-- }
-- ```
-- 
-- **Output JSON object**
-- ```
-- {
--   "xprv": "xprv9uZghWCSYwDho7us3q1WLBjVYx2xzVJNT8qNo4P9i8wa3tQJYbffzztTF6wXjuorG49NXahqraWsrVUmy3uTJLkvSYXyDLnHHU1GJibUk2t",
--   "xpub": "xpub68Z371jLPJn11bzL9rYWhKgE6ysTPx2DpMkybSnmGUUYvgjT68yvYoCw6PP8Vo7YoZRC6iqrfpixEUG694KgHPYYnydGuEYDwjESStYxYxe",
--   "signature": "3045022100af9bf94c4959328b56861ca5f175b5e59014cb5bd2a5fcee2e95b1563dbc652e0220411ff01751af64d6b7209908fc58f527b07a0a9258eee7be7aa5704136954b02",
--   "coin_signature": "af9bf94c4959328b56861ca5f175b5e59014cb5bd2a5fcee2e95b1563dbc652e411ff01751af64d6b7209908fc58f527b07a0a9258eee7be7aa5704136954b02"
-- }
-- ```
-- 
-- ## Example Input JSON object for ETH
-- ```
-- {
--    "masterKeyId": "5aef3e3f-7927-49b2-b252-bf84b6980f95",
--    "coin": "eth",
--    "msgHash": "45a0ee821b05400f513891bbb567a99139f3df72e9e1d4b48186841cc5996d2f"
-- }
-- ```
--
-- ## Example Input JSON object for XPRV 
-- ```
-- {
--    "import": true,
--    "xprvEncId": "5aef3e3f-7927-49b2-b252-bf84b6980f95",
--    "wrapKeyId": "02e5c697-87cd-45b6-8163-957fa5e13370",
--    "name": "Imported Key"
-- }
-- ```
--
-- ## References
-- - https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
-- - https://xrpl.org/sign.html
-- 
-- ### Release Notes
--  V 1.0 Initial Release
--
--  V 2.0 
--  - Added XRP Transaction Signature Support
--  - Added Private Key flag and checking
---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------
----------      COMMON UTILITIES     ----------
---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------
----------------- Debug Logging ---------------
local DEBUG = {}
local DEBUG_N = 1
function debug(msg)
  DEBUG[DEBUG_N] = msg
  DEBUG_N = DEBUG_N + 1
end
----------------- Constant --------------------
local PRIVATE_WALLET_VERSION =  "0488ADE4"
local PUBLIC_WALLET_VERSION = "0488B21E"
local FIRST_HARDENED_CHILD = 2147483648
local PUBLIC_KEY_COMPRESSED_LENGTH = 33
local N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
------------- BIP32 key structure -------------
local key = {["version"]="",
    ["depth"]="",       -- 1 byte
    ["index"]="",       -- 4 byte child number
    ["fingerprint"]="", -- 4 byte parent fingerprint
    ["chain_code"]="",  -- 32 byte
    ["key"]="",         -- 33 byte long key
    ["checksum"]="",    -- checksum of all above
    ["is_private"] = ""} -- 1 bit flag

function create_ASN1_private_key(key_byte)
  while string.len(key_byte) < 64 do
    key_byte = '00' .. key_byte
  end
  return "302E0201010420".. key_byte .."A00706052B8104000A"
end
-- return hex of exported key
function decode_key(exported_master_key_serialized)
  local blob = Blob.from_base58(exported_master_key_serialized)
  return blob:hex()
end
-- deserialize bip32 key
function deserialize(exported_master_key_serialized)
    hex_key = decode_key(exported_master_key_serialized)

    key.version = string.sub(hex_key, 1, 8)
    key.depth = string.sub(hex_key, 9, 10)
    key.index = string.sub(hex_key, 11, 18)
    key.fingerprint = string.sub(hex_key, 19, 26)
    key.chain_code = string.sub(hex_key, 27, 90)
    key.key = string.sub(hex_key, 91, 156)

    if key.version == "0488ADE4" then
        key.is_private = 1
    else
        key.is_private = 0
    end

    key.checksum = string.sub(hex_key, 157, 164)
    return key
end
-- import ec key into sdkms
-- this helps to evaluate public key from private key
function import_ec_key(blob)
    local sobject = assert(Sobject.import { name = "ec", obj_type = "EC", elliptic_curve = "SecP256K1", value = blob, transient = true })
    return sobject
end
-- export secret key that holds the BIP32 master key --
-- export BIP32 master key from SDKMS ---
function export_secret_key(keyId)
    return Sobject { kid = keyId }:export().value
end

---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------
----------           UTXO            ----------
---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------

---------- integer to bytearry impl -----------
---------- utils methods ----------------------
local random = math.random
-- convert number into hex string 
function num_2_hex(num, size)
    local hexstr = '0123456789ABCDEF'
    local s = ""
    while num > 0 do
        local mod = math.fmod(num, 16)
        s = string.sub(hexstr, mod+1, mod+1) .. s
        num = math.floor(num / 16)
    end
    if (string.len(s) < size) then
        local offset = string.rep("0", size-string.len(s))
        s = offset..s
    end
    return s
end
---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------
------------- Parse Derivation Path -----------
---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------
function split(str, pat)
    local t = {}
    local fpat = "(.-)" .. pat
    local last_end = 1
    local s, e, cap = str:find(fpat, 1)
    while s do
        if s ~= 1 or cap ~= "" then
            table.insert(t,cap)
        end
        last_end = e+1
        s, e, cap = str:find(fpat, last_end)
    end
    if last_end <= #str then
        cap = str:sub(last_end)
        table.insert(t, cap)
    end
    return t
end
-- extract co-ordinate from complate ec public key
-- first half of last 64 bit is x-cordinate and second half is y-cordinate
function extract_coordinates_from_ASN1_public_key(key_byte)
    return string.sub(key_byte, 49, 176)
end
-- return ec curve co-ordinate from private key
function get_point_coordinates_from_private_key(key_byte)
    local asn1_ec_key = create_ASN1_private_key(key_byte)
    local blob = Blob.from_hex(asn1_ec_key)
    local ec_key = import_ec_key(blob)
    local asn1_public_key = ec_key.pub_key:hex()
    local coordinate = extract_coordinates_from_ASN1_public_key(asn1_public_key)
    return coordinate
end
-- compress key co-ordinate
local TWO = BigNum.from_bytes_be(Blob.from_hex("02"))
local ZERO = BigNum.from_bytes_be(Blob.from_hex("00"))
function is_even(n)
  if (n % TWO):to_bytes_be() == ZERO:to_bytes_be() then
    return true
  else
    return false
  end
end
function compress_public_key(x, y)
    local a = BigNum.from_bytes_be(Blob.from_hex(y))
    local b = BigNum.from_bytes_be(Blob.from_hex("02"))
    local c = BigNum.from_bytes_be(Blob.from_hex("00"))

    if is_even(a) then
        return "02"..x
    else 
        return "03"..x
    end 
end
-- return public key from private key 
function public_key_for_private_key(key_byte)
    local point = get_point_coordinates_from_private_key(key_byte)
    return compress_public_key(string.sub(point, 1, 64), string.sub(point, 65, 128))
end
-- parse input path
function parse_path(child_path)
    local path_table = split(child_path, "/")
    return path_table
end
-- import chain-code as hmac key
-- sign data as from hmac key
function get_hmac(hmac_key, data)
    local sobject = assert(Sobject.import { name = "hmac", obj_type = "HMAC", value = Blob.from_hex(hmac_key), transient = true })
    local mac =  assert(sobject:mac { data = Blob.from_hex(data), alg = 'SHA512'}).digest
    return mac:hex()
end
-- return ripmd160 digest
function hash160(data)
    local sha256_hash = assert(digest { data = Blob.from_hex(data), alg = 'SHA256' }).digest:hex()
    local ripmd160_hash = assert(digest { data = Blob.from_hex(sha256_hash), alg = 'RIPEMD160' }).digest
    return ripmd160_hash:hex()
end
-- add private keys
function add_private_keys(k1, k2)
    local a = BigNum.from_bytes_be(Blob.from_hex(k1))
    local b = BigNum.from_bytes_be(Blob.from_hex(k2))
    a:add(b)
    a:mod(BigNum.from_bytes_be(Blob.from_hex(N)))   
    hex_key = a:to_bytes_be():hex()
    if (string.len( hex_key ) < 66) then
        local offset = string.rep("0", 32-string.len( hex_key ))
        hex_key = offset..hex_key
    end
    return hex_key
end
-- return scalar addition of point
function addPublicKeys(k1, k2)
    --[[ local x1 =  BigNum.from_bytes_be(Blob.from_hex(string.sub(k1, 1, 64)))
    local y1 =  BigNum.from_bytes_be(Blob.from_hex(string.sub(k1, 65, 128))) ]]--
    local secP256K1 =EcGroup.from_name('SecP256K1')
    local comp_key_1 = Blob.from_hex(k1)
  	local pt_1 = secP256K1:point_from_binary(comp_key_1)
    local x1 = pt_1:x()
    local y1 = pt_1:y()
  	local comp_key_2 = Blob.from_hex(k2)
  	local pt = secP256K1:point_from_binary(comp_key_2)
    local x2 = pt:x()
    local y2 = pt:y()
  	local p1 = secP256K1:point_from_components(x1, y1)
    local p2 = secP256K1:point_from_components(x2, y2)
    local p3 = p1 + p2
    return compress_public_key(p3:x():to_bytes_be():hex(), p3:y():to_bytes_be():hex())
end
-- checksum: double sha256 of serialized key
function get_check_sum(child_key)
    local child_key_string = child_key.version.. child_key.depth..  child_key.fingerprint.. child_key.index.. child_key.chain_code.. child_key.key
    local sha256_hash1 = assert(digest { data = Blob.from_hex(child_key_string), alg = 'SHA256' }).digest:hex()
    local sha256_hash2 = assert(digest { data =  Blob.from_hex(sha256_hash1), alg = 'SHA256' }).digest:hex()
    return sha256_hash2
end
-- derive new child key from parent key
function derive_new_child(parent_key, child_idx)
    local data = ""
    -- if index is greater than equal to first hardend key
    if tonumber(child_idx) >= FIRST_HARDENED_CHILD then
        data = parent_key.key
    else
        -- parent is private
        -- data equal to public key of parent private
        if parent_key.version == PRIVATE_WALLET_VERSION then
            data = public_key_for_private_key(string.sub(parent_key.key, 3, 66))
        else
            -- key is public
            -- data equal to parent key
           data = parent_key.key
        end
    end
    
    -- concatenate index into data
    local index_hex = num_2_hex(child_idx, 8)
    data = data..index_hex
    hmac = get_hmac(parent_key.chain_code, data)

    child_key = {
        index = index_hex,
        chain_code = string.sub(hmac, 65, 128),
        depth = num_2_hex(tonumber(parent_key.depth + 1), 2),
        is_private = parent_key.is_private,
    }
  
    if parent_key.version == PRIVATE_WALLET_VERSION then
        child_key.version = PRIVATE_WALLET_VERSION 
        fingerprint = hash160(public_key_for_private_key(string.sub(parent_key.key, 3, 66))) 
        child_key.fingerprint = string.sub(fingerprint, 1, 8)
        -- appending 00 to make key size 33 bit
        child_key.key = "00"..tostring(add_private_keys(string.sub(hmac, 1, 64), parent_key.key))
    else
        child_key.version = PUBLIC_WALLET_VERSION
        fingerprint = hash160(parent_key.key)
        child_key.fingerprint = string.sub(fingerprint, 1, 8)
        key_bytes = public_key_for_private_key(string.sub(hmac, 1, 64))
        child_key.key = addPublicKeys(key_bytes, parent_key.key)
    end
    
   child_key.checksum = string.sub(get_check_sum(child_key), 1, 8)
  
    return child_key
end
-- serialize child key and encode into base58
function serialize(child_key)
    local child_key_string = table.concat({child_key.version, child_key.depth, child_key.fingerprint, child_key.index, 
        child_key.chain_code, child_key.key, child_key.checksum}
    )
    local blob = Blob.from_hex(child_key_string)
    return  blob:base58()
end
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
-----------            ETH            -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
function get_rs(signature)
  local signature_length = tonumber(string.sub(signature, 3, 4), 16) + 2

  local r_length = tonumber(string.sub(signature, 7, 8), 16)
  local r_left = 9
  local r_right = r_length*2 + r_left - 1
  local r = string.sub(signature, r_left, r_right)
  local s_left = r_right + 5
  local s_right = signature_length*2
  local s_length = tonumber(string.sub(signature, s_left-2, s_left-1), 16)
  local s = string.sub(signature, s_left, s_right)

  -- If s is negative, change it to (-s:mod(N))
  local sign = tonumber(string.sub(s, 1, 2), 16)
  if (sign > 127) then
    s = BigNum.from_bytes_be(~Blob.from_hex(s))
    s:add(BigNum.from_bytes_be(Blob.from_hex("01")))
    s:mod(BigNum.from_bytes_be(Blob.from_hex(N)))
    s = s:hex()
  end

  return {
    r = r,
    s = s
  }
end
function set_length_left(msg, len)
  local msg_len = string.len(msg)
  if (msg_len > len*2) then
    -- This one's too big: truncate it
    return string.sub(msg, msg_len - len*2 + 1)
  else
    -- Otherwise: pad it
    return string.rep("0", len*2 - msg_len)..msg
  end
end
function get_eth_v(r,s)
  local a = BigNum.from_bytes_be(Blob.from_hex(r))
  local b = BigNum.from_bytes_be(Blob.from_hex("02"))
  a:mod(b)
  if a:to_bytes_be()[1] == "" then
    return "1B"
  else
    return "1C"
  end
end
function get_eth_signature(signature)
  local rs = get_rs(signature)
  local ethereum_signature = set_length_left(rs.r, 32)..set_length_left(rs.s, 32)
  return ethereum_signature..get_eth_v(rs.r, rs.s)
end
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
----------- Main method for ETH       -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
function sign_eth(input)
    local exported_master_key_serialized = export_secret_key(input.masterKeyId)
    local master_key = deserialize(exported_master_key_serialized:bytes())

    local private_key = string.sub(master_key.key, 3, 66)

    -- import private key as asn1 ec key
    local asn1_ec_key = create_ASN1_private_key(private_key)
    local blob = Blob.from_hex(asn1_ec_key)
    local ec_child_key = import_ec_key(blob)

    local signature = assert(ec_child_key:sign { hash = Blob.from_hex(input.msgHash), hash_alg = "SHA256", deterministic_signature = true }).signature

    return {
      coin = input.coin,
      signature = signature:hex():lower()
    }
end
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
----------- Main method for XRP       -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
function sign_xrp(input)
    local exported_master_key_serialized = export_secret_key(input.masterKeyId)
    local master_key = deserialize(exported_master_key_serialized:bytes())

    local private_key = string.sub(master_key.key, 3, 66)

    -- import private key as asn1 ec key
    local asn1_ec_key = create_ASN1_private_key(private_key)
    local blob = Blob.from_hex(asn1_ec_key)
    local ec_child_key = import_ec_key(blob)

    local signature = assert(ec_child_key:sign { hash = Blob.from_hex(input.msgHash), hash_alg = "SHA256", deterministic_signature = true }).signature

    return {
      coin = input.coin,
      signature = signature:hex():lower()
    }
end
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
----------- Main method for UTXO      -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
function sign_utxo(input)
    local exported_master_key_serialized = export_secret_key(input.masterKeyId)
    local master_key = deserialize(exported_master_key_serialized:bytes())
    local indices = parse_path(input.path)

    for i = 2, #indices do
        child_key = derive_new_child(master_key, tonumber(indices[i]))
        master_key = child_key
    end

    local child_key_serialized = serialize(child_key)
    local asn1_ec_key = create_ASN1_private_key(string.sub(child_key.key, 3, 66))
    local blob = Blob.from_hex(asn1_ec_key)
    local ec_child_key = import_ec_key(blob)
    local sign_input = { hash = Blob.from_hex(input.msgHash), hash_alg = "SHA256", deterministic_signature = true }
    local signature = assert(ec_child_key:sign(sign_input)).signature

  return {
    coin = input.coin,
    signature = signature:hex():lower()
  }
end
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
----------- Main method for Import    -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
function run_import(input)
  local xprvEnc = assert(Sobject { kid = input.xprvEncId }):export().value
  local wrapKey = assert(Sobject { kid = input.wrapKeyId })

  local xprv = assert(wrapKey:decrypt { cipher = xprvEnc }).plain:bytes()
  xprv = string.gsub(xprv,"%s+","")
  xprv = string.gsub(xprv,"\n+","")
  local sobject = assert(Sobject.import { name = input.name, obj_type = "SECRET", value = Blob.from_bytes(xprv), transient = false })

  return {
    kid = sobject.kid
  }
end
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
----------- Main method for Plugin    -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
function run(input)
  if input.import == true then
    return run_import(input)
  end

  if input.debug == true then
    if input.coin == "eth" then return { result = sign_eth(input); debug = DEBUG }
    elseif input.coin == "xrp" then return { result = sign_xrp(input); debug = DEBUG }
    elseif input.coin == "utxo" then return { result = sign_utxo(input); debug = DEBUG }
    else return { error = "unsupported coin" } end
  end

  if input.coin == "eth" then
    return {
      coin = input.coin,
      signature = sign_eth(input).signature
    }

  elseif input.coin == "xrp" then
    return {
      coin = input.coin,
      signature = sign_xrp(input).signature
    }
  elseif input.coin == "utxo" then
    return {
      coin = input.coin,
      signature = sign_utxo(input).signature
    }
  else
    return { error = "unsupported coin" }
  end
end
