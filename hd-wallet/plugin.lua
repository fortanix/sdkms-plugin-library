-- Name: HD Wallet
-- Version: 1.3
-- Description:## Short Description
-- Implementation of hierarchical deterministic wallets (or "HD Wallets")
--
-- ## Introduction
-- The plugin derives a child key in a given path from a master key, and signs
-- a transaction hash. The child key is transient; it only exists during the
-- plugin execution.
--
-- ## Use cases
--
-- The plugin can be used to sign a transaction for UTXO and Ethereum.
--
-- ## Setup
--
-- Create a security object named SEED of HMAC type.
--
-- ## Input/Output JSON object format for signing
--
---- ### Input
-- For UTXO coin (BTC, LTC, BCH, etc.):
--{
--  "coin": "utxo",
--  "path": "m/2",
--  "msg_hash": "45a0ee821b05400f513891bbb567a99139f3df72e9e1d4b48186841cc5996d2f"
--}
--
-- For ETH:
--{
--  "path": "m/0'/42",
--  "coin": "eth",
--  "msg_hash": "45a0ee821b05400f513891bbb567a99139f3df72e9e1d4b48186841cc5996d2f"
--}
--
-- ### Output
--{
--  "coin": "eth",\
--  "xpub": "<HD-Wallet-Public-Key>",
--  "r" : " "
--  "s" : " "
--  "signature": "<ECDSA signature>"
--}
--
-- * `path`:           Path of key to be derived for signature, e.g: m/2/10H
-- * `msg_hash`:       32-byte SHA-3 message hash
-- * `coin`:           coin type utxo or eth
-- * `xpub`:           BIP0032 public key
-- * `signature`:      ECDSA signature

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

---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------
----------           BIP 32          ----------
---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------

-- Named "point(p)" in the spec
--
-- Here, DSM is used only for scalar multiplication. As an improvement, this
-- function could perform the scalar multiplication using the Lua class.
----------------- Constant --------------------

local FIRST_HARDENED_CHILD   = 0x80000000

---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------
----------           BIP 32 UTILITY         ----------
---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------
local N = BigNum.from_bytes_be(Blob.from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"))

function maybe_hard(path)
   if string.sub(path, -1) == '\'' then
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

local function serialize_bip32_pubkey(blob)

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
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
-----------            ETH            -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
local SEED =  "SEED"

local function sign_eth(path, msg_hash)
    local child_key
    
    local hmac_seed =  assert(Sobject {name = SEED}, "SEED not found")
	
  	local parent_key = assert(hmac_seed:derive {
      name = "MASTER_KEY",
      key_type = "BIP32", 
      key_size = 0,  -- Unused but necessary, unfortunately
      mechanism = { bip32_master_key = { network = "mainnet" }},
      transient = true})	
     
	local indices = parse_path(path)
  
  	for i = 2, #indices do
      if tonumber(indices[i]) < FIRST_HARDENED_CHILD then 
      	child_key = assert(parent_key:transform {
      		name = "SIGNING_KEY",
      		key_type = "BIP32", 
      		key_size = 0,  -- Unused but necessary, unfortunately
      		mechanism = { bip32_weak_child = { index = tonumber(indices[i]) }},
      		transient = true
  		})
      else 
      	child_key = assert(parent_key:derive {
      		name = "SIGNING_KEY",
      		key_type = "BIP32", 
      		key_size = 0,  -- Unused but necessary, unfortunately
      		mechanism = { bip32_hardened_child = { index = tonumber(indices[i]) }},
      		transient = true
  		})
      	
      end
      parent_key = child_key
  end
	  
    local signature = assert(parent_key:sign {
        hash                    = Blob.from_hex(msg_hash),
        hash_alg                = "SHA256",
        deterministic_signature = true
    }, "cannot sign").signature
  	local rs = format_rs(signature:hex())

    return {
      signature = signature:hex():lower(),
      r = rs.r:to_bytes_be_zero_pad(32):hex():lower(),
      s = rs.s:to_bytes_be_zero_pad(32):hex():lower(),
      pub_key = serialize_bip32_pubkey(parent_key.pub_key)
  }
end

----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
-----------           UTXO            -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------

local function sign_utxo(path, msg_hash)
  	local child_key
    
    local hmac_seed =  assert(Sobject {name = SEED}, "SEED not found")
	
  	local parent_key = assert(hmac_seed:derive {
      name = "MASTER_KEY",
      key_type = "BIP32", 
      key_size = 0,  -- Unused but necessary, unfortunately
      mechanism = { bip32_master_key = { network = "mainnet" }},
      transient = true})	
     
	local indices = parse_path(path)
  
  	for i = 2, #indices do
      if tonumber(indices[i]) < FIRST_HARDENED_CHILD then 
      	child_key = assert(parent_key:transform {
      		name = "SIGNING_KEY",
      		key_type = "BIP32", 
      		key_size = 0,  -- Unused but necessary, unfortunately
      		mechanism = { bip32_weak_child = { index = tonumber(indices[i]) }},
      		transient = true
  		})
      else 
      	child_key = assert(parent_key:derive {
      		name = "SIGNING_KEY",
      		key_type = "BIP32", 
      		key_size = 0,  -- Unused but necessary, unfortunately
      		mechanism = { bip32_hardened_child = { index = tonumber(indices[i]) }},
      		transient = true
  		})
      	
      end
      parent_key = child_key
  end
	  
    local sig = assert(parent_key:sign({
        hash                    = Blob.from_hex(msg_hash),
        hash_alg                = "SHA256",
        deterministic_signature = true
    }))

    return {
        signature = sig.signature:hex():lower(),
        xpub = serialize_bip32_pubkey(parent_key.pub_key)
    }
end

----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
----------- Main method for Plugin    -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
function run(input)
    local required_fields = {"path", "msg_hash", "coin" }
    for _, field in pairs(required_fields) do
        if not input[field] then
            error("missing argument " .. field)
        end
    end

    local response
    if input.coin == "eth" then
        response = sign_eth(input.path, input.msg_hash)
    elseif input.coin == "utxo" then
        response = sign_utxo(input.path, input.msg_hash)
    else
        return { error = "unsupported coin " .. input.coin }
    end
    response.coin = input.coin

    return response
end
