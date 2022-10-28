-- Name: HD Wallet
-- Version: 1.3
-- Description:
-- This plugin implements hierarchical deterministic wallets (or "HD Wallets") BIP0032 protocol.
--
-- ## Introduction
-- The plugin derives a child key (xprv, xpub) in a in a given path from a
-- master key, and signs a transaction hash. The child key is transient; it
-- only exists during the plugin execution. This version of the plugin requires
-- the master key to be exportable. In upcoming version 2.0, this condition is
-- removed for better security.
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
local PRIVATE_WALLET_VERSION = "0488ADE4"
local PUBLIC_WALLET_VERSION  = "0488B21E"
local FIRST_HARDENED_CHILD   = 0x80000000

 -- The order of the secp256k1 curve. It is < 2^256, e.g. every integer modulo
 -- the order fits in 32 bytes.
local ORDER_SECP256K1     = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
local ORDER_SECP256K1_LEN = 32


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
        s = offset .. s
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

  local asn1 = Blob.from_hex("302E0201010420" .. blob .. "A00706052B8104000A")

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
    return "02" .. x
  else
    return "03" .. x
  end
end

-- return public key from private key
local function public_from_private(private_key_bytes)
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
  local derived_bytes

  if tonumber(child_index) >= FIRST_HARDENED_CHILD then
    derived_bytes = parent_key.key_bytes
  elseif parent_key.version == PRIVATE_WALLET_VERSION then
    -- parent is private, we take the public key of the parent
    derived_bytes = public_from_private(string.sub(parent_key.key_bytes, 3, 66))
  elseif parent_key.version == PUBLIC_WALLET_VERSION then
    -- parent is public already
    derived_bytes = parent_key.key_bytes
  else
    error("unkown version encountered when deriving")
  end

  local index_hex = num_2_hex(child_index, 8)
  derived_bytes = derived_bytes .. index_hex

  -- import chain-code as hmac key
  local sobject = assert(Sobject.import {
    obj_type  = "HMAC",
    value     = Blob.from_hex(parent_key.chain_code),
    transient = true
  }, "cannot import HMAC Sobject")
  local hmac =  assert(sobject:mac {
    data = Blob.from_hex(derived_bytes),
    alg  = 'SHA512'
  }).digest:hex()
  local child_key = {
    index      = index_hex,
    chain_code = string.sub(hmac, 65, 128),
    depth      = num_2_hex(tonumber(parent_key.depth + 1), 2)
  }

  if parent_key.version == PRIVATE_WALLET_VERSION then
    child_key.version = PRIVATE_WALLET_VERSION
    local pub_key = public_from_private(string.sub(parent_key.key_bytes, 3, 66))
    child_key.parent_fgpt = string.sub(hash_160(pub_key), 1, 8)

    -- append 00 to make key size 33 bytes
    local a = BigNum.from_bytes_be(Blob.from_hex(string.sub(hmac, 1, 64)))
    local b = BigNum.from_bytes_be(Blob.from_hex(parent_key.key_bytes))
    a:add(b)
    a:mod(BigNum.from_bytes_be(Blob.from_hex(ORDER_SECP256K1)))
    local hex_key = a:to_bytes_be():hex()

    if (string.len( hex_key ) < 66) then
      local offset = string.rep("0", 32-string.len( hex_key ))
      hex_key = offset .. hex_key
    end

    child_key.key_bytes = "00" .. tostring(hex_key)
  else
    child_key.version = PUBLIC_WALLET_VERSION
    child_key.parent_fgpt = string.sub(hash_160(parent_key.key_bytes), 1, 8)
    local key_bytes = public_from_private(string.sub(hmac, 1, 64))

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

local function sign_eth(master_key, msg_hash)
  local private_key = string.sub(master_key.key_bytes, 3, 66)
  local signing_key = import_ec_key(private_key)

  local sig = assert(signing_key:sign {
    hash                    = Blob.from_hex(msg_hash),
    hash_alg                = "SHA256",
    deterministic_signature = true
  }, "cannot sign").signature

  -- Parse r, s from DER signature. It is a SEQUENCE of two elements of
  -- length R_LENGTH. Normally, they both fit in 32 bytes but SEC1 does not
  -- prevent serializing them with more bytes and padding with 0x00 so we check
  -- the structure for sanity.
  assert(sig:slice(1, 1) == Blob.from_hex("30"), "bad signature") -- SEQUENCE
  local sig_len = tonumber(sig:slice(2, 2):hex(), 16)
  assert(#sig == sig_len + 2, "bad signature length")
  assert(
    sig:slice(3, 3) == Blob.from_hex("02"), "bad signature"
  ) -- INTEGER
  local r_len = tonumber(sig:slice(4, 4):hex(), 16)
  local r_left = 2 + 2
  local r_right = r_left + r_len
  local s_left = r_right + 2
  assert(
    sig:slice(r_right + 1, r_right + 1) == Blob.from_hex("02"), "bad signature"
  ) -- INTEGER
  local s_len = tonumber(sig:slice(r_right + 2, r_right + 2):hex(), 16)
  assert(#sig == 2 + 2 + r_len + 2 + s_len)
  local s_right = s_left + s_len

  -- The structure is correct. Get the integers.
  local r = BigNum.from_bytes_be(sig:slice(r_left, r_right))
  local s = BigNum.from_bytes_be(sig:slice(s_left, s_right))

  -- Maybe flip 's', see TODO: reference
  local N = BigNum.from_bytes_be(Blob.from_hex(ORDER_SECP256K1))

  if s > N - s then
    s = N - s
  end
  local r_bytes_padded = r:to_bytes_be_zero_pad(ORDER_SECP256K1_LEN)
  local s_bytes_padded = s:to_bytes_be_zero_pad(ORDER_SECP256K1_LEN)

  -- Get Ethereum 'v' value
  -- Recall that 'r' is the abscissa of a point in the elliptic curve,
  -- therefore, an element of Fp. The probability of r mod order being
  -- different than r is overwhelmingly low, so we assume that and only set `v`
  -- according to the parity.
  -- See e.g. https://bitcoin.stackexchange.com/questions/38351
  local one = Blob.from_hex("01")
  local v = Blob.from_hex("1B")
  if r_bytes_padded:slice(#r_bytes_padded, #r_bytes_padded) & one == one then
    v = Blob.from_hex("1C")
  end


  return {
    signature      = sig:hex(),
    coin_signature = (r_bytes_padded .. s_bytes_padded .. v):hex()
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
  })).signature

  return {
    signature = sig:hex()
  }
end

----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
----------- Main method for Plugin    -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
function run(input)
  local required_fields = { "master_key_id", "msg_hash" }
  for _, field in pairs(required_fields) do
    if not input[field] then
      error("missing argument " .. field)
    end
  end

  -- This is a critical security operation. On version 2.0 of the plugin, the
  -- plan is to use a non-exportable security object.
  local master_sobject = assert(
    Sobject { kid = input.master_key_id }, "cannot access master key"
  )
  local master_key_bytes = assert(
    master_sobject:export().value, "cannot export master key"
  )

  local master_key = deserialize_bip32(master_key_bytes)

  local response
  if input.coin == "eth" then
    response = sign_eth(master_key, input.msg_hash)
  elseif input.coin == "utxo" then
    response = sign_utxo(master_key, input.path, input.msg_hash)
  else
    return { error = "unsupported coin " .. input.coin }
  end
  response.coin = input.coin

  return response
end
