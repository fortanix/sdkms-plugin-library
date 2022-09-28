-- Name: HD Wallet
-- Version: 1.1
-- Description:##
-- This plugin implements hierarchical deterministic wallets (or "HD Wallets") BIP0032 protocol.
-- 
-- ### ## Introduction
-- The plugin allows to derive child key (xprv, xpub) from a master key in a deterministic way, and/or sign transaction hashes for UTXO and ethereum type crypto coins.
-- 
-- ## Use cases
-- 
-- The plugin can be used to
-- 
-- - Derive child key for UTXO
-- - Derive child key for ethereum
-- - Sign transaction for UTXO
-- - Sign transaction for ethereum
-- - Import wrapped private key for storage in Smartkey
--
-- ## Setup
-- 
-- - Generate HD-Wallets master key manually
-- **Example Master Key:** `xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U` 
-- - Import master key in SDKMS as wrapped secret key using plugin import method
-- 
-- ## Input/Output JSON object format for signing
-- 
-- ### Input
-- For UTXO coin (BTC, LTC, BCH, etc.):
--{
--  "masterKeyId": "5aef3e3f-7927-49b2-b252-bf84b6980f95",
--  "coin": "utxo",
--  "path": "m/2",
--  "msgHash": "45a0ee821b05400f513891bbb567a99139f3df72e9e1d4b48186841cc5996d2f"
--}
--
-- For ETH:
--{
--  "masterKeyId": "5aef3e3f-7927-49b2-b252-bf84b6980f95",
--  "coin": "eth",
--  "msgHash": "45a0ee821b05400f513891bbb567a99139f3df72e9e1d4b48186841cc5996d2f"
--}
--
-- ### Output
--{
--  "xpub": "<HD-Wallet-Public-Key>",
--  "coin_signature": "<Bitcoin-canonicalized-ECDSA-signature>",
--  "signature": "<ECDSA signature>"
--}
--
-- ## Input/Output JSON object format for import
--
-- For XPRV Import:
--{
--  "import": true,
--  "xprvEncId": "5aef3e3f-7927-49b2-b252-bf84b6980f95",
--  "wrapKeyId": "02e5c697-87cd-45b6-8163-957fa5e13370",
--  "name": "Imported Key"
--}
--
-- ## Variable Explanations:
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
--  - Added input function and support for bech32


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
local FIRST_HARDENED_CHILD = 0x80000000
-
- -- The order of the secp256k1 curve
local N = BigNum.from_bytes_be(Blob.from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"))
local PUBLIC_KEY_COMPRESSED_LENGTH = 33

------------- BIP32 key structure -------------
local key = {
    ["version"]="",
    ["depth"]="",       -- 1 byte depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
    ["index"]="",       -- 4 byte child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
    ["fingerprint"]="", -- 4 byte the fingerprint of the parent's key (0x00000000 if master key)
    ["chain_code"]="",  -- 32 byte the chain code
    ["key"]="",         -- 33 byte key data : the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
    ["checksum"]=""     -- checksum of all above
}

function createASN1privateKey(keybyte)
  while string.len(keybyte) < 64 do
    keybyte = '00' .. keybyte
  end
  return "302E0201010420".. keybyte .."A00706052B8104000A"
end

-- deserialize bip32 key
function deserialize(exported_master_key_serialized)
    local hex_key = Blob.from_base58(exported_master_key_serialized):hex()
 
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

-- import ec key into sdkms
-- this will help to evaluate public key from private key
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
function num2hex(num, size)
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
-- compress key co-ordinate
function compressPublicKey(x, y)
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
function publicKeyForPrivateKey(keybyte)
    local asn1_ec_key = createASN1privateKey(keybyte)
    local blob = Blob.from_hex(asn1_ec_key)
    local ec_key = import_ec_key(blob)
    local asn1_publicKey = ec_key.pub_key:hex()

    -- extract co-ordinate from complate ec public key
    -- first half of last 64 bit is x-cordinate and second half is y-cordinate
    local point = string.sub(asn1_publicKey, 49, 176)
    return compressPublicKey(string.sub(point, 1, 64), string.sub(point, 65, 128))
end

-- return ripmd160 digest
function hash160(data)
    local sha256_hash = assert(digest { data = Blob.from_hex(data), alg = 'SHA256' }).digest:hex()
    local ripmd160_hash = assert(digest { data = Blob.from_hex(sha256_hash), alg = 'RIPEMD160' }).digest
    return ripmd160_hash:hex()
end

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

    -- import chain-code as hmac key
    -- sign data as from hmac key
    local sobject = assert(Sobject.import { name = "hmac", obj_type = "HMAC", value = Blob.from_hex(parent_key.chain_code), transient = true })
    local mac =  assert(sobject:mac { data = Blob.from_hex(data), alg = 'SHA512'}).digest
    local hmac = mac:hex()

    childKey = {
        index = index_hex,
        chain_code = string.sub(hmac, 65, 128),
        depth = num2hex(tonumber(parent_key.depth + 1), 2)
    }
    if parent_key.version == PRIVATE_WALLET_VERSION then
        childKey.version = PRIVATE_WALLET_VERSION 
        fingerprint = hash160(publicKeyForPrivateKey(string.sub(parent_key.key, 3, 66))) 
        childKey.fingerprint = string.sub(fingerprint, 1, 8)

        -- appending 00 to make key size 33 bit
        local a = BigNum.from_bytes_be(Blob.from_hex(string.sub(hmac, 1, 64)))
        local b = BigNum.from_bytes_be(Blob.from_hex(parent_key.key))
        a:add(b)
        a:mod(BigNum.from_bytes_be(Blob.from_hex(N)))   
        hex_key = a:to_bytes_be():hex()

        if (string.len( hex_key ) < 66) then
            local offset = string.rep("0", 32-string.len( hex_key ))
            hex_key = offset..hex_key
        end

        childKey.key = "00"..tostring(hex_key)
    else
        childKey.version = PUBLIC_WALLET_VERSION
        fingerprint = hash160(parent_key.key)
        childKey.fingerprint = string.sub(fingerprint, 1, 8)
        keyBytes = publicKeyForPrivateKey(string.sub(hmac, 1, 64))

        local secP256K1 = EcGroup.from_name('SecP256K1')
        local comp_key_1 = Blob.from_hex(keyBytes)
        local pt_1 = secP256K1:point_from_binary(comp_key_1)
        local x1 = pt_1:x()
        local y1 = pt_1:y()
        local comp_key_2 = Blob.from_hex(parent_key.key)
        local pt = secP256K1:point_from_binary(comp_key_2)
        local x2 = pt:x()
        local y2 = pt:y()
        local p1 = secP256K1:point_from_components(x1, y1)
        local p2 = secP256K1:point_from_components(x2, y2)
        local p3 = p1 + p2
        
        childKey.key = compressPublicKey(p3:x():to_bytes_be():hex(), p3:y():to_bytes_be():hex())
    end
    
    -- checksum: double sha256 of serialized key
    local chlid_key_string = childKey.version.. childKey.depth..  childKey.fingerprint.. childKey.index.. childKey.chain_code.. childKey.key
    local sha256_hash1 = assert(digest { data = Blob.from_hex(chlid_key_string), alg = 'SHA256' }).digest:hex()
    childKey.checksum = assert(digest { data =  Blob.from_hex(sha256_hash1), alg = 'SHA256' }).digest:hex()
      
    return childKey
end

----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
----------- Main method for ETH       -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
function run_eth(input)
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
----------- Main method for UTXO      -----------
----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
function run_utxo(input)
    local exported_master_key_serialized = export_secret_key(input.masterKeyId)
    local master_key = deserialize(exported_master_key_serialized:bytes())

    local indices = {}
    local fpat = "(.-)" .. "/"
    local last_end = 1
    local s, e, cap = input.path:find(fpat, 1)

    while s do
        if s ~= 1 or cap ~= "" then
            table.insert(indices, cap)
        end
        last_end = e+1
        s, e, cap = str:find(fpat, last_end)
    end
    if last_end <= #str then
        cap = str:sub(last_end)
        table.insert(indices, cap)
    end

    for i = 2, #indices do
        child_key = derive_new_child(master_key, tonumber(indices[i]))
        master_key = child_key
    end

    -- serialize child key and encode into base58
    local chlid_key_string = table.concat({child_key.version, child_key.depth, child_key.fingerprint, child_key.index, 
        child_key.chain_code, child_key.key, child_key.checksum}
    )
    local blob = Blob.from_hex(chlid_key_string)
    
    local child_key_serialized = blob:base58()
   
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
