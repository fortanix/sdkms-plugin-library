-- Name: HD Wallet
-- Version: 1.3
-- Description:
-- This plugin implements hierarchical deterministic wallets (or "HD Wallets") BIP0032 protocol.
--
-- ## Introduction
-- The plugin derives a child key (xprv, xpub) in a in a given path from a master key, and signs a transaction hash.
--
-- ## Use cases
--
-- The plugin can be used to sign a transaction for UTXO and Ethereum.
--
-- ## Setup
--
-- Import the BIP32 master key as a BIP32 object - text import.
-- **Example Master Key:**
-- `xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U`
--
-- ## Input/Output JSON object format for signing
--
-- ### Input
-- For UTXO coin (BTC, LTC, BCH, etc.):
--{
--  "master_key_id": "5aef3e3f-7927-49b2-b252-bf84b6980f95",
--  "coin": "utxo",
--  "path": "m/2",
--  "msg_hash": "45a0ee821b05400f513891bbb567a99139f3df72e9e1d4b48186841cc5996d2f"
--}
--
-- For ETH:
--{
--  "master_key_id": "5aef3e3f-7927-49b2-b252-bf84b6980f95",
--  "coin": "eth",
--  "msg_hash": "45a0ee821b05400f513891bbb567a99139f3df72e9e1d4b48186841cc5996d2f"
--}
--
-- ### Output
--{
--  "xpub": "<HD-Wallet-Public-Key>",
--  "coin_signature": "<Bitcoin-canonicalized-ECDSA-signature>",
--  "signature": "<ECDSA signature>"
--}
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
-- ## References
--
-- - https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
-- - https://en.bitcoin.it/wiki/Bech32
--
-- ### Release Notes
--  - Initial release

----------------- Constant --------------------
local PRIVATE_WALLET_VERSION =  "0488ADE4"
local PUBLIC_WALLET_VERSION = "0488B21E"
local FIRST_HARDENED_CHILD = 0x80000000

 -- The order of the secp256k1 curve
local N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"


---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------
----------           BIP 32          ----------
---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------

-- Convert integer into hex string
local function num_2_hex(num, size)
    local hexstr = '0123456789ABCDEF'
    local s = ""
    while num > 0 do
        local mod = math.fmod(num, 16)
        s = string.sub(hexstr, mod + 1, mod + 1) .. s
        num = math.floor(num / 16)
    end
    if (string.len(s) < size) then
        local offset = string.rep("0", size-string.len(s))
        s = offset..s
    end
    return s
end

local function deserialize_bip32(private_key)
  local hex_key = assert(
    Blob.from_base58(private_key:bytes()),
    "cannot base58 decode private key"
  ):hex()

  local key = {
    ["version"]     = string.sub(hex_key, 1, 8),     --  8 bytes
    ["depth"]       = string.sub(hex_key, 9, 10),    --  1 byte
    ["index"]       = string.sub(hex_key, 11, 18),   --  4 bytes
    ["parent_fgpt"] = string.sub(hex_key, 19, 26),   --  4 bytes
    ["chain_code"]  = string.sub(hex_key, 27, 90),   -- 32 bytes
    ["key_bytes"]   = string.sub(hex_key, 91, 156),  -- 33 bytes
    ["checksum"]    = string.sub(hex_key, 157, 164), --  8 bytes - checksum
  }

  if key.version ~= PRIVATE_WALLET_VERSION and key.version ~= PUBLIC_WALLET_VERSION then
    error("Unexpected key version")
  end

  return key
end

-- Create a transient EC Sobject with the given value
local function import_ec_key(blob)

  -- First format the key in ASN1
  while string.len(blob) < 64 do
    blob = '00' .. blob
  end

  local asn1 = Blob.from_hex("302E0201010420".. blob .."A00706052B8104000A")

  -- Import into DSM as transient key
  return assert(Sobject.import {
    obj_type       = "EC",
    elliptic_curve = "SecP256K1",
    value          = asn1,
    transient      = true
  })
end

local function maybe_hard(path)
  if string.sub(path, -1) == 'H' then
    return tostring(tonumber(string.sub(path, 0, #path - 1)) + FIRST_HARDENED_CHILD)
  else
    return tostring(tonumber(path))
  end
end

local function parse_path(path)
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

-- compress key co-ordinate
local function compress_public_key(x, y)
  local a = BigNum.from_bytes_be(Blob.from_hex(y))
  local b = BigNum.from_bytes_be(Blob.from_hex("02"))
  local c = BigNum.from_bytes_be(Blob.from_hex("00"))

  if (a % b):to_bytes_be() == c:to_bytes_be() then
    return "02"..x
  else
    return "03"..x
  end
end

-- return public key from private key
local function public_key_for_private_key(private_key_bytes)
  local sobject = import_ec_key(private_key_bytes)
  local asn1_public_key = sobject.pub_key:hex()

  -- extract coordinate from complete ec public key
  -- first half of last 64 bit is x-coordinate and second half is y-coordinate
  local point = string.sub(asn1_public_key, 49, 176)
  return compress_public_key(string.sub(point, 1, 64), string.sub(point, 65, 128))
end

-- returns RIPEMD-160(SHA-256(data))
local function hash_160(data)
  local sha256_hash = assert(digest {
    data = Blob.from_hex(data),
    alg  = 'SHA256'
  }).digest:hex()
  local ripemd160_hash = assert(digest {
    data = Blob.from_hex(sha256_hash),
    alg  = 'RIPEMD160'
  }).digest

  return ripemd160_hash:hex()
end

-- derive new child key from parent key
local function derive_new_child(parent_key, child_index)
  local data

  -- if index is greater than equal to first hardened key
  if tonumber(child_index) >= FIRST_HARDENED_CHILD then
    data = parent_key.key_bytes
  else
  -- parent is private
  -- data equal to public key of parent private
  if parent_key.version == PRIVATE_WALLET_VERSION then
    data = public_key_for_private_key(string.sub(parent_key.key_bytes, 3, 66))
  else
    -- key is public
    -- data equal to parent key
    data = parent_key.key_bytes
    end
  end

  -- concatenate index into data
  local index_hex = num_2_hex(child_index, 8)
  data = data..index_hex

  -- import chain-code as hmac key
  local sobject = assert(Sobject.import {
    obj_type  = "HMAC",
    value     = Blob.from_hex(parent_key.chain_code),
    transient = true
  }, "cannot import HMAC Sobject")
  local hmac =  assert(sobject:mac {
    data = Blob.from_hex(data),
    alg  = 'SHA512'
  }).digest:hex()
  local child_key = {
    index      = index_hex,
    chain_code = string.sub(hmac, 65, 128),
    depth      = num_2_hex(tonumber(parent_key.depth + 1), 2)
  }

  if parent_key.version == PRIVATE_WALLET_VERSION then
    child_key.version = PRIVATE_WALLET_VERSION
    local pub_key = public_key_for_private_key(string.sub(parent_key.key_bytes, 3, 66))
    child_key.parent_fgpt = string.sub(hash_160(pub_key), 1, 8)

    -- append 00 to make key size 33 bytes
    local a = BigNum.from_bytes_be(Blob.from_hex(string.sub(hmac, 1, 64)))
    local b = BigNum.from_bytes_be(Blob.from_hex(parent_key.key_bytes))
    a:add(b)
    a:mod(BigNum.from_bytes_be(Blob.from_hex(N)))
    local hex_key = a:to_bytes_be():hex()

    if (string.len( hex_key ) < 66) then
      local offset = string.rep("0", 32-string.len( hex_key ))
      hex_key = offset..hex_key
    end

    child_key.key_bytes = "00"..tostring(hex_key)
  else
    child_key.version = PUBLIC_WALLET_VERSION
    child_key.parent_fgpt = string.sub(hash_160(parent_key.key_bytes), 1, 8)
    local key_bytes = public_key_for_private_key(string.sub(hmac, 1, 64))

    local secP256K1 = EcGroup.from_name('SecP256K1')
    local comp_key_1 = Blob.from_hex(key_bytes)
    local pt_1 = secP256K1:point_from_binary(comp_key_1)
    local x1 = pt_1:x()
    local y1 = pt_1:y()
    local comp_key_2 = Blob.from_hex(parent_key.key_bytes)
    local pt = secP256K1:point_from_binary(comp_key_2)
    local x2 = pt:x()
    local y2 = pt:y()
    local p1 = secP256K1:point_from_components(x1, y1)
    local p2 = secP256K1:point_from_components(x2, y2)
    local p3 = p1 + p2

    child_key.key_bytes = compress_public_key(
      p3:x():to_bytes_be():hex(), p3:y():to_bytes_be():hex()
    )
  end

  -- checksum: double sha256 of serialized key
  local child_key_string =
    child_key.version ..
    child_key.depth ..
    child_key.parent_fgpt ..
    child_key.index ..
    child_key.chain_code ..
    child_key.key_bytes
  local sha256_hash1 = assert(digest {
    data = Blob.from_hex(child_key_string),
    alg  = 'SHA256'
  }).digest:hex()
  child_key.checksum = assert(digest {
    data = Blob.from_hex(sha256_hash1),
    alg  = 'SHA256'
  }).digest:hex()

  return child_key
end

----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
-----------            ETH            -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------

local function format_rs(signature)
  local signature_length = tonumber(string.sub(signature, 3, 4), 16) + 2
  local r_length = tonumber(string.sub(signature, 7, 8), 16)
  local r_left = 9
  local r_right = r_length*2 + r_left - 1
  local r = BigNum.from_bytes_be(Blob.from_hex(string.sub(signature, r_left, r_right)))

  local s_left = r_right + 5
  local s_right = signature_length * 2
  local s = BigNum.from_bytes_be(Blob.from_hex(string.sub(signature, s_left, s_right)))

  local N_minus_s = BigNum.from_bytes_be(Blob.from_hex(N)) - s

  if s > N_minus_s then
    s = N_minus_s
  end

  return {
    r = r,
    s = s
  }
end

local function get_eth_v(r)
   local a = r:copy()
   a:mod(BigNum.from_int(2))
   if a == BigNum.from_int(0) then
      return "1B"
   else
      return "1C"
   end
end

local function sign_eth(master_key, msg_hash)
  local private_key = string.sub(master_key.key_bytes, 3, 66)
  local signing_key = import_ec_key(private_key)

  local sig = assert(signing_key:sign {
    hash                    = Blob.from_hex(msg_hash),
    hash_alg                = "SHA256",
    deterministic_signature = true
  }, "cannot sign").signature:hex()

  local rs = format_rs(sig)
  local v = get_eth_v(rs.r)
  local r_padded = rs.r:to_bytes_be_zero_pad(32):hex()
  local s_padded = rs.s:to_bytes_be_zero_pad(32):hex()
  local coin_signature = r_padded .. s_padded .. v

  return {
    signature = sig,
    coin_signature = coin_signature
  }
end

----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
-----------           UTXO            -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------

local function sign_utxo(master_key, path, msg_hash)
  local parent_key = master_key
  local child_key

  local indices = parse_path(path)

  -- Obtain last key from path
  for i = 2, #indices do
      child_key = derive_new_child(parent_key, tonumber(indices[i]))
      parent_key = child_key
  end

  local raw_child_key = string.sub(child_key.key_bytes, 3, 66)

  local child_sobject = import_ec_key(raw_child_key)
  local sig = assert(child_sobject:sign({
    hash                    = Blob.from_hex(msg_hash),
    hash_alg                = "SHA256",
    deterministic_signature = true
  })).signature:hex()

  return {
    signature = sig
  }
end

----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
----------- Main method for Plugin    -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
function run(input)
  -- TODO: Sanitize input
  local master_sobject = assert(Sobject { kid = input.master_key_id })
  local raw_master_key = assert(master_sobject:export().value, "cannot export master key")

  local master_key = deserialize_bip32(raw_master_key)

  local sig
  if input.coin == "eth" then
    sig = sign_eth(master_key, input.msg_hash)
  elseif input.coin == "utxo" then
    sig = sign_utxo(master_key, input.path, input.msg_hash)
  else
    return { error = "unsupported coin" }
  end
  sig.coin = input.coin
  return sig
end
