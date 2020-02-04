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
   ["checksum"]=""    -- checksum of all above
}

---- Functions common to UTXO and Eth

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

   return key
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

-- return public key from private key
function compute_public_point(keybyte)
   local secp256k1 = EcGroup.from_name('SecP256K1')
   local secret_scalar = BigNum.from_bytes_be(Blob.from_hex(keybyte))
   local public_point = secp256k1:generator():mul(secret_scalar)
   return public_point:to_binary():hex()
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

-- derive new child key from parent key
function derive_new_child(parent_key, childIdx)
   local index_hex = num2hex(childIdx, 8)

   local input

   if parent_key.version == PRIVATE_WALLET_VERSION and tonumber(childIdx) < FIRST_HARDENED_CHILD then
      -- parent is private
      -- input equal to public key of parent private
      input = compute_public_point(string.sub(parent_key.key, 3, 66))
   else
      input = parent_key.key
   end

   input = input .. index_hex

   local hmac_key = assert(Sobject.import { name = "BIP32 mac", obj_type = "HMAC", value = Blob.from_hex(parent_key.chain_code), transient = true })
   local hmac = assert(hmac_key:mac { data = Blob.from_hex(input), alg = 'SHA512'}).digest:hex()

   child_key = {
      index = index_hex,
      chain_code = string.sub(hmac, 65, 128),
      -- XXX this fails for deep paths > 10
      depth = num2hex(tonumber(parent_key.depth + 1), 2),
   }

   if parent_key.version == PRIVATE_WALLET_VERSION then
      child_key.version = parent_key.version
      fingerprint = hash160(compute_public_point(string.sub(parent_key.key, 3, 66)))
      child_key.fingerprint = string.sub(fingerprint, 1, 8)
      -- prefixing 00 to make key size 33 bytes
      child_key.key = "00" .. tostring(add_scalar(string.sub(hmac, 1, 64), parent_key.key))
   else
      child_key.version = parent_key.version
      fingerprint = hash160(parent_key.key)
      child_key.fingerprint = string.sub(fingerprint, 1, 8)
      keyBytes = compute_public_point(string.sub(hmac, 1, 64))
      child_key.key = add_points(keyBytes, parent_key.key)
   end

   local child_key_string = child_key.version .. child_key.depth .. child_key.fingerprint .. child_key.index .. child_key.chain_code .. child_key.key
   child_key.checksum = string.sub(sha256d(child_key_string), 1, 8)

   return child_key
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

function serialize(key)
   local key_string = table.concat({key.version, key.depth, key.fingerprint, key.index,
                                    key.chain_code, key.key, key.checksum})
   return Blob.from_hex(key_string):base58()
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

----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
----------- Main method for Plugin    -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
function run(input)
   local master_key_obj = assert(Sobject { kid = input.master_key_id }, "master key not found")
   local master_key_bytes = assert(master_key_obj:export(), "master key not exportable")

   local master_key = deserialize(master_key_bytes.value:bytes())

   if input.coin == "eth" then
      return sign_eth(master_key, input)
   elseif input.coin == "utxo" then
      return sign_utxo(master_key, input)
   else
      return nil, "unsupported coin"
   end
end
