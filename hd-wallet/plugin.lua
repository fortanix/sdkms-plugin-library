-- Name: HD Wallet
-- Version: 1.0
-- Description:## Short Description
-- This plugin implements hierarchical deterministic wallets (or "HD Wallets") BIP0032 protocol.
-- 
-- ### ## Introduction
-- The plugin allows to derive child key (xprv, xpub) from a master key in a deterministic way, and/or sign transaction hashes for UTXO and ethereum type crypto coin.
-- 
-- ## Use cases
-- 
-- The plugin can be used to
-- 
-- - Derive child key for UTXO
-- - Derive child key for ethereum
-- - Sign transaction for UTXO
-- - Sign transaction for ethereum
-- 
-- ## Setup
-- 
-- - Generate HD-Wallets master key manually
-- **Example Master Key:** `xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U` 
-- - Importe master key in SDKMS as secret raw key
-- 
-- ## Input/Output JSON object format
-- 
-- For UTXO coin (BTC, LTC, BCH, etc.):
-- {
--    "masterKeyId": "5aef3e3f-7927-49b2-b252-bf84b6980f95",
--    "coin": "utxo",
--    "path": "m/2",
--    "msgHash": "45a0ee821b05400f513891bbb567a99139f3df72e9e1d4b48186841cc5996d2f"
-- }
-- For ETH:
-- {
--   "masterKeyId": "5aef3e3f-7927-49b2-b252-bf84b6980f95",
--   "coin": "eth",
--   "msgHash": "45a0ee821b05400f513891bbb567a99139f3df72e9e1d4b48186841cc5996d2f"
-- }
-- For XPRV Import:
-- {
   -- "import": true,
   -- "xprvEncId": "5aef3e3f-7927-49b2-b252-bf84b6980f95",
   -- "wrapKeyId": "02e5c697-87cd-45b6-8163-957fa5e13370",
   -- "name": "Imported Key"
-- }
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
-- ## Example Input/Output JSON object
-- 
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
-- 
-- ```
-- {
--   "xprv": "xprv9uZghWCSYwDho7us3q1WLBjVYx2xzVJNT8qNo4P9i8wa3tQJYbffzztTF6wXjuorG49NXahqraWsrVUmy3uTJLkvSYXyDLnHHU1GJibUk2t",
--   "xpub": "xpub68Z371jLPJn11bzL9rYWhKgE6ysTPx2DpMkybSnmGUUYvgjT68yvYoCw6PP8Vo7YoZRC6iqrfpixEUG694KgHPYYnydGuEYDwjESStYxYxe",
--   "signature": "3045022100af9bf94c4959328b56861ca5f175b5e59014cb5bd2a5fcee2e95b1563dbc652e0220411ff01751af64d6b7209908fc58f527b07a0a9258eee7be7aa5704136954b02",
--   "coin_signature": "af9bf94c4959328b56861ca5f175b5e59014cb5bd2a5fcee2e95b1563dbc652e411ff01751af64d6b7209908fc58f527b07a0a9258eee7be7aa5704136954b02"
-- }
-- ```
-- 
-- ## References
-- 
-- - https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
-- 
-- ### Release Notes
--  - Initial release

----------------- Constant --------------------
local PRIVATE_WALLET_VERSION =  "0488ADE4"
local PUBLIC_WALLET_VERSION = "0488B21E"
local FIRST_HARDENED_CHILD = 0x80000000

local PUBLIC_KEY_COMPRESSED_LENGTH = 33

-- The order of the secp256k1 curve
local N = BigNum.from_bytes_be(Blob.from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"))

------------- BIP32 key structure -------------
local key = {
   ["version"]="",     -- 4 byte version
   ["depth"]="",       -- 1 byte
   ["index"]="",       -- 4 byte child number
   ["fingerprint"]="", -- 4 byte parent fingerprint
   ["chain_code"]="",  -- 32 byte
   ["key"]="",         -- 33 byte long key
   ["checksum"]="",    -- checksum of all above
   ["is_private"]=""   -- 1 bit flag 
}

---- Functions common to UTXO and Eth

function createASN1privateKey(keybyte)
  while string.len(keybyte) < 64 do
    keybyte = '00' .. keybyte
  end
  return "302E0201010420".. keybyte .."A00706052B8104000A"
end

-- return hex of exported key
function decode_key(exported_master_key_serialized)
  local blob = Blob.from_base58(exported_master_key_serialized)
  return blob:hex()
end

function ecdsa_sign(private_key, input)
   -- Assumed to be previously zero-padded if needed
   assert(#private_key == 64)
   local asn1_ec_key = "302E0201010420".. private_key .."A00706052B8104000A"
   local blob = Blob.from_hex(asn1_ec_key)
   local subkey = assert(Sobject.import { name = "bip32 ec", obj_type = "EC", elliptic_curve = "SecP256K1", value = blob, transient = true })
   return assert(subkey:sign { hash = input, hash_alg = "SHA256", deterministic_signature = true }).signature
end

-- deserialize bip32 key
function deserialize(exported_master_key_serialized)
   local hex_key = Blob.from_base58(exported_master_key_serialized):hex()

   if #hex_key ~= 164 then
      error("Unexpected key length")
   end

   key.version = string.sub(hex_key, 1, 8)
   key.depth = string.sub(hex_key, 9, 10)
   key.index = string.sub(hex_key, 11, 18)
   key.fingerprint = string.sub(hex_key, 19, 26)
   key.chain_code = string.sub(hex_key, 27, 90)
   key.key = string.sub(hex_key, 91, 156)
   key.checksum = string.sub(hex_key, 157, 164)

   if key.version ~= PRIVATE_WALLET_VERSION and key.version ~= PUBLIC_WALLET_VERSION then
      error("Unexpected key version")
   end

-- Evaluate if this is the same logic as above
   if key.version == "0488ADE4" then
     key.is_private = 1
   else
     key.is_private = 0
   end

   return key
end

-- import ec key into sdkms
-- this will hepl to evaluate public key from private key
function import_ec_key(blob)
    local sobject = assert(Sobject.import { name = "ec", obj_type = "EC", elliptic_curve = "SecP256K1", value = blob, transient = true })
    return sobject
end

-- export secret key that holds the BIP32 master key --
-- export BIP32 master key from SDKMS ---
function export_secret_key(keyId)
    return Sobject { kid = keyId }:export().value
end

function format_rs(signature)
   local signature_length = tonumber(string.sub(signature, 3, 4), 16) + 2
   local r_length = tonumber(string.sub(signature, 7, 8), 16)
   local r_left = 9
   local r_right = r_length*2 + r_left - 1
   local r = BigNum.from_bytes_be(Blob.from_hex(string.sub(signature, r_left, r_right)))

   local s_left = r_right + 5
   local s_right = signature_length*2
   local s_length = tonumber(string.sub(signature, s_left-2, s_left-1), 16)
   local s = BigNum.from_bytes_be(Blob.from_hex(string.sub(signature, s_left, s_right)))

   local N_minus_s = N - s

   if s > N_minus_s then
      s = N_minus_s
   end

   return {
      r = r,
      s = s
   }
end

---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------
----------           UTXO            ----------
---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------

---------- integer to bytearry impl -----------
---------- utils methods ----------------------
local random = math.random
-- reverse an array element
function reverse_array(arr)
    local i, j = 1, #arr
    while i < j do
        arr[i], arr[j] = arr[j], arr[i]
        i = i + 1
        j = j - 1
    end
end

function bytearray(int)
    local bytes = {}
    for i = 0, 3 do
        bytes[i+1] = (int >> (i * 8)) & 0xFF
    end
    reverse_array(bytes)
    return bytes
end

-- convert number into hex string
function num2hex(num, size)
   return BigNum.from_int(num):to_bytes_be_zero_pad(size/2):hex()
end

function maybe_hard(path)
   if string.sub(path, -1) == 'H' then
      return tostring(tonumber(string.sub(path, 0, #path - 1)) + FIRST_HARDENED_CHILD)
   else
      return tostring(tonumber(path))
   end
end

local function getUUID()
    local template ='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
    return string.gsub(template, '[xy]', function (c)
        local v = (c == 'x') and random(0, 0xf) or random(8, 0xb)
        return string.format('%x', v)
    end)
end


-- parse input path
function parse_path(path)
   local t = {}
   local fpat = "(.-)" .. "/"
   local last_end = 1
   local s, e, cap = path:find(fpat, 1)
   while s do
      if s ~= 1 or cap ~= "" then
         table.insert(t, maybe_hard(cap))
      end
      last_end = e+1
      s, e, cap = path:find(fpat, last_end)
   end
   if last_end <= #path then
      cap = path:sub(last_end)
      table.insert(t, maybe_hard(cap))
   end
   return t
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
function extractCoordinatesFromASN1PublicKey(keybyte)
    return string.sub(keybyte, 49, 176)
end

-- return ec curve co-ordinate from private key
function GetPointCoordinatesFromPrivateKey(keybyte)
    local asn1_ec_key = createASN1privateKey(keybyte)
    local blob = Blob.from_hex(asn1_ec_key)
    local ec_key = import_ec_key(blob)
    local asn1_publicKey = ec_key.pub_key:hex()
    local coordinate = extractCoordinatesFromASN1PublicKey(asn1_publicKey)
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

function compressPublicKey(x, y)
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
-- TODO Look to merge this with the lines below
function publicKeyForPrivateKey(keybyte)
    local point = GetPointCoordinatesFromPrivateKey(keybyte)
    return compressPublicKey(string.sub(point, 1, 64), string.sub(point, 65, 128))
end

-- return public key from private key
function compute_public_point(keybyte)
   local secp256k1 = EcGroup.from_name('SecP256K1')
   local secret_scalar = BigNum.from_bytes_be(Blob.from_hex(keybyte))
   local public_point = secp256k1:generator():mul(secret_scalar)
   return public_point:to_binary():hex()
end

-- import chain-code as hmac key
-- sign data as from hmac key
function get_hmac(hmac_key, data)
    local sobject = assert(Sobject.import { name = "hmac", obj_type = "HMAC", value = Blob.from_hex(hmac_key), transient = true })
    local mac =  assert(sobject:mac { data = Blob.from_hex(data), alg = 'SHA512'}).digest
    return mac:hex()
end

-- return RIPEMD(SHA-256(data))
function hash160(data)
   local sha256_hash = assert(digest { data = Blob.from_hex(data), alg = 'SHA256' }).digest
   local ripmd160_hash = assert(digest { data = sha256_hash, alg = 'RIPEMD160' }).digest
   return ripmd160_hash:hex()
end

-- Return SHA-256(SHA-256(data))
function sha256d(data)
   local sha256_hash1 = assert(digest { data = Blob.from_hex(data), alg = 'SHA256' }).digest
   local sha256_hash2 = assert(digest { data = sha256_hash1, alg = 'SHA256' }).digest
   return sha256_hash2:hex()
end

-- add two secret scalar values
function add_scalar(k1, k2)
   local a = BigNum.from_bytes_be(Blob.from_hex(k1))
   local b = BigNum.from_bytes_be(Blob.from_hex(k2))
   a:add(b)
   a:mod(N)
   return a:to_bytes_be_zero_pad(32):hex()
end

-- add two EC points
function add_points(k1, k2)
   local secP256K1 = EcGroup.from_name('SecP256K1')
   local pt1 = secP256K1:point_from_binary(Blob.from_hex(k1))
   local pt2 = secP256K1:point_from_binary(Blob.from_hex(k2))
   local pt3 = pt1 + pt2
   return pt3:to_binary():hex()
end

-- add private keys
function addPrivateKeys(k1, k2)
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
    return compressPublicKey(p3:x():to_bytes_be():hex(), p3:y():to_bytes_be():hex())
end

-- checksum: double sha256 of serialized key
function getCheckSum(child_key)
    local chlid_key_string = child_key.version.. child_key.depth..  child_key.fingerprint.. child_key.index.. child_key.chain_code.. child_key.key
    local sha256_hash1 = assert(digest { data = Blob.from_hex(chlid_key_string), alg = 'SHA256' }).digest:hex()
    local sha256_hash2 = assert(digest { data =  Blob.from_hex(sha256_hash1), alg = 'SHA256' }).digest:hex()
    return sha256_hash2
end

-- derive new child key from parent key
-- derive new child key from parent key
function derive_new_child(parent_key, childIdx)
    local data = ""
    -- if index is greater than equal to first hardend key
    if tonumber(childIdx) >= FIRST_HARDENED_CHILD then
        data = parent_key.key
    else
        -- parent is private
        -- data equal to public key of parent private
        if parent_key.version == PRIVATE_WALLET_VERSION then
            data = publicKeyForPrivateKey(string.sub(parent_key.key, 3, 66))
        else
            -- key is public
            -- data equal to parent key
           data = parent_key.key
        end
    end
    
    -- concatenate index into data
    local index_hex = num2hex(childIdx, 8)
    data = data..index_hex
    hmac = get_hmac(parent_key.chain_code, data)

    childKey = {
        index = index_hex,
        chain_code = string.sub(hmac, 65, 128),
        depth = num2hex(tonumber(parent_key.depth + 1), 2),
        is_private = parent_key.is_private,
    }
  
    if parent_key.version == PRIVATE_WALLET_VERSION then
        childKey.version = PRIVATE_WALLET_VERSION 
        fingerprint = hash160(publicKeyForPrivateKey(string.sub(parent_key.key, 3, 66))) 
        childKey.fingerprint = string.sub(fingerprint, 1, 8)
        -- appending 00 to make key size 33 bit
        childKey.key = "00"..tostring(addPrivateKeys(string.sub(hmac, 1, 64), parent_key.key))
    else
        childKey.version = PUBLIC_WALLET_VERSION
        fingerprint = hash160(parent_key.key)
        childKey.fingerprint = string.sub(fingerprint, 1, 8)
        keyBytes = publicKeyForPrivateKey(string.sub(hmac, 1, 64))
        childKey.key = addPublicKeys(keyBytes, parent_key.key)
    end
    
   childKey.checksum = string.sub(getCheckSum(childKey), 1, 8)
  
    return childKey
end

function derive_public_key(key)
   if key.version ~= PRIVATE_WALLET_VERSION then
      return key
   end

   local xpub = key
   xpub.version = PUBLIC_WALLET_VERSION
   xpub.key = compute_public_point(key.key)
   local xpub_string = xpub.version .. xpub.depth .. xpub.fingerprint .. xpub.index .. xpub.chain_code .. xpub.key
   xpub.checksum = string.sub(sha256d(xpub_string), 1, 8)

   return xpub
end

-- serialize child key and encode into base58
function serialize(child_key)
    local chlid_key_string = table.concat({child_key.version, child_key.depth, child_key.fingerprint, child_key.index, 
        child_key.chain_code, child_key.key, child_key.checksum}
    )
    local blob = Blob.from_hex(chlid_key_string)
    return  blob:base58()
end

----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
----------- Main method for UTXO      -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
function run_utxo(input)
    local exported_master_key_serialized = export_secret_key(input.masterKeyId)
    local master_key = deserialize(exported_master_key_serialized:bytes())
    local indices = parse_path(input.path)

    for i = 2, #indices do
        child_key = derive_new_child(master_key, tonumber(indices[i]))
        master_key = child_key
    end

    local child_key_serialized = serialize(child_key)
    local asn1_ec_key = createASN1privateKey(string.sub(child_key.key, 3, 66))
    local blob = Blob.from_hex(asn1_ec_key)
    local ec_child_key = import_ec_key(blob)
    local sign_input = { hash = Blob.from_hex(input.msgHash), hash_alg = "SHA256", deterministic_signature = true }
    local signature = assert(ec_child_key:sign(sign_input)).signature

  return {
    coin = input.coin,
    signature = signature:hex():lower()
    --rs = get_rs(signature:hex())
  }
end

function sign_utxo(master_key, input)
   local indices = parse_path(input.path)

   for i = 2, #indices do
      child_key = derive_new_child(master_key, tonumber(indices[i]))
      master_key = child_key
   end

   output = {}

   if (input.msg_hash ~= nil) and (#input.msg_hash) == 64 then
      local signature = ecdsa_sign(string.sub(child_key.key, 3, 66), Blob.from_hex(input.msg_hash)):hex()

      local rs = format_rs(signature)
      local rs_hex = rs.r:to_bytes_be_zero_pad(32):hex() .. rs.s:to_bytes_be_zero_pad(32):hex()

      output.signature = signature:lower()
      output.coin_signature = rs_hex:lower()
   end

   if child_key.version == PRIVATE_WALLET_VERSION then
      output.xprv = serialize(child_key)
      output.xpub = serialize(derive_public_key(child_key))
   else
      output.xpub = serialize(child_key)
   end

   return output
end

----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
-----------            ETH            -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------

function get_eth_v(r,s)
   local a = r:copy()
   a:mod(BigNum.from_int(2))
   if a == BigNum.from_int(0) then
      return "1B"
   else
      return "1C"
   end
end

function sign_eth(master_key, input)
   local private_key = string.sub(master_key.key, 3, 66)

   local signature = ecdsa_sign(private_key, Blob.from_hex(input.msg_hash)):hex()
   local rs = format_rs(signature)
   local v = get_eth_v(rs.r, rs.s)
   local coin_signature = rs.r:to_bytes_be_zero_pad(32):hex() .. rs.s:to_bytes_be_zero_pad(32):hex() .. v

   return {
      signature = signature:lower(),
      coin_signature = coin_signature:lower()
   }
end

function run_eth(input)
    local exported_master_key_serialized = export_secret_key(input.masterKeyId)
    local master_key = deserialize(exported_master_key_serialized:bytes())

    local private_key = string.sub(master_key.key, 3, 66)

    -- import private key as asn1 ec key
    local asn1_ec_key = createASN1privateKey(private_key)
    local blob = Blob.from_hex(asn1_ec_key)
    local ec_child_key = import_ec_key(blob)

    local signature = assert(ec_child_key:sign { hash = Blob.from_hex(input.msgHash), hash_alg = "SHA256", deterministic_signature = true }).signature
    local EthSignature = get_EthSignature(signature:hex())

    return {
      coin = input.coin,
      signature = signature:hex():lower()
      --rs = get_rs(signature:hex()),
      --eth_signature = EthSignature:lower()
    }
end

----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
----------- Main method for XRP       -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
function run_xrp(input)
    local exported_master_key_serialized = export_secret_key(input.masterKeyId)
    local master_key = deserialize(exported_master_key_serialized:bytes())

    local private_key = string.sub(master_key.key, 3, 66)

    -- import private key as asn1 ec key
    local asn1_ec_key = createASN1privateKey(private_key)
    local blob = Blob.from_hex(asn1_ec_key)
    local ec_child_key = import_ec_key(blob)

    local signature = assert(ec_child_key:sign { hash = Blob.from_hex(input.msgHash), hash_alg = "SHA256", deterministic_signature = true }).signature

    return {
      coin = input.coin,
      signature = signature:hex():lower()
      --rs = get_rs(signature:hex()),
      --eth_signature = EthSignature:lower()
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
    if input.coin == "eth" then return { result = run_eth(input); debug = DEBUG }
    elseif input.coin == "xrp" then return { result = run_xrp(input); debug = DEBUG }
    elseif input.coin == "utxo" then return { result = run_utxo(input); debug = DEBUG }
    else return { error = "unsupported coin" } end
  end

  if input.coin == "eth" then
    return {
      coin = input.coin,
      signature = run_eth(input).signature
    }

  elseif input.coin == "xrp" then
    return {
      coin = input.coin,
      signature = run_xrp(input).signature
    }
  elseif input.coin == "utxo" then
    return {
      coin = input.coin,
      signature = run_utxo(input).signature
    }
  else
    return { error = "unsupported coin" }
  end
end
