-- Name: HD Wallet
-- Version: 1.3
-- Description:
-- This plugin implements hierarchical deterministic wallets (or "HD Wallets")
-- BIP0032 protocol.
--
-- ## Introduction
-- The plugin derives a child key in a given path from a master key, and signs
-- a transaction hash. The child key is transient; it only exists during the
-- plugin execution. This version of the plugin requires the master key to be
-- exportable. In upcoming version 2.0, this condition is removed for better
-- security.
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
--  "coin": "eth",
--  "xpub": "<HD-Wallet-Public-Key>",
--  "coin_signature": "<Bitcoin-canonicalized-ECDSA-signature>",
--  "signature": "<ECDSA signature>"
--}
--
-- * `master_key_id`:  UUID of master key imported in SDKMS
-- * `path`:           Path of key to be derived for signature, e.g: m/2/10H
-- * `msg_hash`:       32-byte SHA-3 message hash
-- * `coin`:           coin type utxo or eth
-- * `xpub`:           BIP0032 public key
-- * `signature`:      ECDSA signature
-- * `coin_signature`: Bitcoin canonicalized ECDSA signature
--
-- ## References
--
-- - https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
-- - https://en.bitcoin.it/wiki/Bech32
--
-- ### Release Notes
--  - Initial release
--  - 1.2 - See github.com/fortanix/sdkms-plugin-library/pull/6
--  - 1.3 - Code refactor for legibility w.r.t. the BIP0032 specification.
--          Several fixes over 1.2:
--          - Fix compilation errors, code lint
--          - Removed unused functions and wrong documentation
--          - Use bytes everywhere
--          - Specify that we support private -> private key derivation.

----------------- Constant --------------------
local PRIVATE_WALLET_VERSION = "0488ADE4"
local PUBLIC_WALLET_VERSION  = "0488B21E"
local FIRST_HARDENED_CHILD   = 0x80000000

 -- The order of the secp256k1 curve. It is < 2^256, e.g. every integer modulo
 -- the order fits in 32 bytes.
local ORDER_SECP256K1     = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
local ORDER_SECP256K1_LEN = 32

---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------
----------      Fortanix DSM         ----------
---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------

-- Create a transient EC Sobject with the given value
local function import_ec_key(blob)
  assert(#blob == 32, "cannot import ec key due to bad length")
  local asn1 =
    Blob.from_hex("302E0201010420")
    .. blob
    .. Blob.from_hex("A00706052B8104000A")

  return assert(Sobject.import {
    obj_type       = "EC",
    elliptic_curve = "SecP256K1",
    value          = asn1,
    transient      = true
  })
end

-- RIPEMD-160(SHA-256(data))
local function hash_160(data)
  local sha256_hash = assert(digest {
    data = data,
    alg  = 'SHA256'
  }).digest
  local ripemd160_hash = assert(digest {
    data = sha256_hash,
    alg  = 'RIPEMD160'
  }).digest

  return ripemd160_hash
end

---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------
----------           BIP 32          ----------
---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------

-- Named "point(p)" in the spec
local function public_blob_from_private_blob(blob)
  assert(#blob == 32)
  local sobject = import_ec_key(blob)
  local asn1_public_key = sobject.pub_key

  -- extract coordinates from ASN1 public key
  -- first half of last 64 bytes is x-coordinate and second half is y-coordinate
  assert(#asn1_public_key, 88)
  local x = asn1_public_key:slice(25, 25 + 32 - 1)

  -- Point compression: If y is even, return 0x02 || x. Else, return 0x03 || x.
  -- (See SEC1 sec. 2.3.3)
  local one = Blob.from_hex("01")
  local y_last_byte = asn1_public_key:slice(88, 88)
  if y_last_byte & one == one then
    return Blob.from_hex("03") .. x
  end
  return Blob.from_hex("02") .. x
end

local function ser_32(i)
  return Blob.from_hex(string.format("%08X", i))
end

local function deserialize_bip32(blob)
  local key = {
    ["version"]     = blob:slice(1, 4),   --  4 bytes
    ["depth"]       = blob:slice(5, 5),   --  1 byte
    ["parent_fgpt"] = blob:slice(6, 9),   --  4 bytes
    ["index"]       = blob:slice(10, 13), --  4 bytes
    ["chain_code"]  = blob:slice(14, 45), -- 32 bytes
    -- ignored                            --  1 0x00 byte
    ["key_bytes"]   = blob:slice(47, 78), -- 32 bytes
  }

  if key.version:hex() ~= PRIVATE_WALLET_VERSION then
    error("Unexpected key version " .. key.version)
  end

  return key
end

-- Assumes that key is private. Obtains public key and serializes according to
-- the spec.
local function serialize_bip32_pubkey(key)
  local version = Blob.from_hex(PUBLIC_WALLET_VERSION)
  local key_bytes = public_blob_from_private_blob(key["key_bytes"])

  local blob =
    version ..
    key.depth ..
    key.parent_fgpt ..
    key.index ..
    key.chain_code ..
    key_bytes

  -- Add double SHA-256 checksum
  local inner = assert(digest {
    data = blob,
    alg  = 'SHA256'
  }).digest
  local checksum = assert(digest {
    data = inner,
    alg  = 'SHA256'
  }).digest:slice(1, 4)

  blob = blob .. checksum

  return blob:base58()
end

local function compute_fingerprint(key)
  local pub_key = public_blob_from_private_blob(key["key_bytes"])
  return hash_160(pub_key):slice(1, 4)
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

-- We only implement private parent key → private child key
--
-- See https://en.bitcoin.it/wiki/BIP_0032
local function derive_private_child(parent_key, index)
  local parent_version = parent_key.version:hex()
  if parent_version == PUBLIC_WALLET_VERSION then
    error("cannot derive private child from public parent")
  elseif parent_version ~= PRIVATE_WALLET_VERSION then
    error("encountered unknown version " .. parent_version)
  end

  local ser_32_index = ser_32(index)
  local data_for_hmac -- depends on whether the child is hardened

  local ser_32_k_par = parent_key['key_bytes']
  if tonumber(index) >= FIRST_HARDENED_CHILD then
    data_for_hmac = Blob.from_hex("00") .. ser_32_k_par .. ser_32_index
  else
    data_for_hmac = public_blob_from_private_blob(ser_32_k_par) .. ser_32_index
  end

  -- Import parent chain code as hmac key
  local sobject = assert(Sobject.import {
    obj_type  = "HMAC",
    value     = parent_key["chain_code"],
    transient = true
  }, "cannot import HMAC Sobject")

  local hmac =  assert(sobject:mac {
    data = data_for_hmac,
    alg  = 'SHA512'
  }).digest

  -- Split I into two 32-byte sequences
  local i_left = hmac:slice(1, 32)
  local i_right = hmac:slice(33, 64)

  -- The returned child key ki is parse256(IL) + kpar (mod n).
  local k_par = BigNum.from_bytes_be(parent_key["key_bytes"])
  local child_key_scalar = BigNum.from_bytes_be(i_left)
  child_key_scalar:add(k_par)
  child_key_scalar:mod(BigNum.from_bytes_be(Blob.from_hex(ORDER_SECP256K1)))
  -- Pad to 32 bytes in case of leading zeros
  local child_key_scalar_bytes = Blob.from_hex(
    child_key_scalar:to_bytes_be_zero_pad(32):hex()
  )

  local depth = string.format("%02X", tonumber(parent_key.depth:hex()) + 1)
  local parent_fgpt = compute_fingerprint(parent_key)

  return {
    version     = Blob.from_hex(PRIVATE_WALLET_VERSION),
    depth       = Blob.from_hex(depth),
    index       = ser_32_index,
    parent_fgpt = parent_fgpt,
    chain_code  = i_right,
    key_bytes   = child_key_scalar_bytes
  }
end

----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
-----------            ETH            -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------

local function sign_eth(master_key, msg_hash)
  local master_key_private_bytes = master_key['key_bytes']
  local signing_key = import_ec_key(master_key_private_bytes)

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
  local r_left = 5
  local r_right = r_left + r_len - 1
  assert(
    sig:slice(r_right + 1, r_right + 1) == Blob.from_hex("02"), "bad signature"
  ) -- INTEGER
  local s_len = tonumber(sig:slice(r_right + 2, r_right + 2):hex(), 16)
  local s_left = r_right + 3
  local s_right = s_left + s_len - 1
  assert(#sig == s_right)

  -- The structure is correct. Get the integers.
  local r = BigNum.from_bytes_be(sig:slice(r_left, r_right))
  local s = BigNum.from_bytes_be(sig:slice(s_left, s_right))

  -- Maybe flip 's'
  local N = BigNum.from_bytes_be(Blob.from_hex(ORDER_SECP256K1))
  if s > N - s then
    s = N - s
  end
  local r_bytes_padded = r:to_bytes_be_zero_pad(ORDER_SECP256K1_LEN)
  local s_bytes_padded = s:to_bytes_be_zero_pad(ORDER_SECP256K1_LEN)

  -- Get Ethereum 'v' value
  -- Recall that 'r' is the abscissa of a point in the elliptic curve,
  -- therefore, an element of Fp. The probability of r mod order being
  -- different than r is overwhelmingly low, so we assume that they are equal
  -- and only set `v` according to the parity.
  -- See e.g. https://bitcoin.stackexchange.com/questions/38351
  local one = Blob.from_hex("01")
  local v = Blob.from_hex("1B")
  if r_bytes_padded:slice(#r_bytes_padded, #r_bytes_padded) & one == one then
    v = Blob.from_hex("1C")
  end

  return {
    xpub           = serialize_bip32_pubkey(master_key),
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
      child_key = derive_private_child(parent_key, tonumber(indices[i]))
      parent_key = child_key
  end

  local child_sobject = import_ec_key(child_key["key_bytes"])
  local sig = assert(child_sobject:sign({
    hash                    = Blob.from_hex(msg_hash),
    hash_alg                = "SHA256",
    deterministic_signature = true
  }))
  local xpub = serialize_bip32_pubkey(child_key)

  return {
    signature = sig.signature:hex(),
    xpub = xpub
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
  ):bytes()

  local master_key_decoded = assert(
    Blob.from_base58(master_key_bytes),
    "cannot base58 decode private key"
  )
  local master_key = deserialize_bip32(master_key_decoded)

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
