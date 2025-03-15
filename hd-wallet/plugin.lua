-- Name: HD Wallet
-- Version: 2.0
-- Description:## Short Description
-- Implementation of hierarchical deterministic wallets (or "HD Wallets")
--
-- ## Introduction
-- The plugin derives a child key in a given path from an HMAC seed, and signs
-- a transaction hash. The child key is transient; it only exists during the
-- plugin execution.
--
-- ## Use cases
--
-- The plugin can be used to sign a transaction for UTXO and Ethereum.
--
-- ## Setup
--
-- Create a security object of HMAC type.
--
-- ## Input/Output JSON object format for signing
--
-- ### Input
-- For UTXO coin (BTC, LTC, BCH, etc.):
--{
--  "hmac_seed_id": "722adb21-107c-4fdf-b28e-2627437815af",
--  "coin": "utxo",
--  "path": "m/2",
--  "msg_hash": "45a0ee821b05400f513891bbb567a99139f3df72e9e1d4b48186841cc5996d2f"
--}
--
-- For ETH:
--{
--  "hmac_seed_id" = "722adb21-107c-4fdf-b28e-2627437815af",
--  "path": "m/0'/42",
--  "coin": "eth",
--  "msg_hash": "45a0ee821b05400f513891bbb567a99139f3df72e9e1d4b48186841cc5996d2f"
--}
--
-- ### Output
--{
--  "coin": "eth",
--  "xpub": "<HD-Wallet-Public-Key>",
--  "signature": "<ECDSA signature>",
--  "coin_signature": "<Bitcoin-canonicalized-ECDSA-signature>",
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
--  - 2.0 - Added native BIP0032 support from sdkms

----------------- Constant --------------------

local FIRST_HARDENED_CHILD   = 0x80000000

---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------
----------      BIP 32 UTILITY       ----------
---------- @@@@@@@@@@@@@@@@@@@@@@@@@ ----------

-- The order of the secp256k1 curve. It is < 2^256, e.g. every integer modulo
-- the order fits in 32 bytes.
local ORDER_SECP256K1     = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
local ORDER_SECP256K1_LEN = 32
local N = BigNum.from_bytes_be(Blob.from_hex(ORDER_SECP256K1))

function maybe_hard(path)
    if (string.sub(path, -1) == 'H') or (string.sub(path, -1) == '\'') then
        return tostring(tonumber(string.sub(path, 0, #path - 1)) + FIRST_HARDENED_CHILD)
    else
        return tostring(tonumber(path))
    end
end

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

function canonicalize_ecdsa_signature(signature)
    local signature_length = tonumber(string.sub(signature, 3, 4), 16) + 2
    local r_length = tonumber(string.sub(signature, 7, 8), 16)
    local r_left = 9
    local r_right = r_length*2 + r_left - 1
    local r = BigNum.from_bytes_be(Blob.from_hex(string.sub(signature, r_left, r_right)))

    local s_left = r_right + 5
    local s_right = signature_length*2
    local s = BigNum.from_bytes_be(Blob.from_hex(string.sub(signature, s_left, s_right)))

    local N_minus_s = N - s

    if s > N_minus_s then
        s = N_minus_s
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
        canonicalize_sig = (r_bytes_padded .. s_bytes_padded .. v):hex():lower()
    }
end

-- Assumes that key is private. Obtains public key and serializes according to
-- the spec.
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

local function sign_eth(hmac_seed_id, path, msg_hash)
    local child_key

    hmac_seed = Sobject { kid =hmac_seed_id}

    local parent_key = assert(hmac_seed:derive {
        key_type = "BIP32",
        key_size = 0,  -- Unused but necessary, unfortunately
        mechanism = { bip32_master_key = { network = "mainnet" }},
        transient = true})

        local indices = parse_path(path)

        for i = 2, #indices do
            if tonumber(indices[i]) < FIRST_HARDENED_CHILD then
                child_key = assert(parent_key:transform {
                    key_type = "BIP32",
                    key_size = 0,  -- Unused but necessary, unfortunately
                    mechanism = { bip32_weak_child = { index = tonumber(indices[i]) }},
                    transient = true
                })
            else
                child_key = assert(parent_key:derive {
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

        rs_sig = canonicalize_ecdsa_signature(signature:hex())

        return {
            signature = signature:hex():lower(),
            coin_signature = rs_sig.canonicalize_sig,
            xpub = serialize_bip32_pubkey(parent_key.pub_key)
        }
    end

    ----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------
    -----------           UTXO            -----------
    ----------- @@@@@@@@@@@@@@@@@@@@@@@@@ -----------

    local function sign_utxo(hmac_seed_id, path, msg_hash)
        local child_key

        hmac_seed = Sobject { kid =hmac_seed_id}

        local parent_key = assert(hmac_seed:derive {
            key_type = "BIP32",
            key_size = 0,  -- Unused but necessary, unfortunately
            mechanism = { bip32_master_key = { network = "mainnet" }},
            transient = true})

            local indices = parse_path(path)

            for i = 2, #indices do
                if tonumber(indices[i]) < FIRST_HARDENED_CHILD then
                    child_key = assert(parent_key:transform {
                        key_type = "BIP32",
                        key_size = 0,  -- Unused but necessary, unfortunately
                        mechanism = { bip32_weak_child = { index = tonumber(indices[i]) }},
                        transient = true
                    })
                else
                    child_key = assert(parent_key:derive {
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
        local required_fields = {"hmac_seed_id","path", "msg_hash", "coin" }
        for _, field in pairs(required_fields) do
            if not input[field] then
                error("missing argument " .. field)
            end
        end

        local response
        if input.coin == "eth" then
            response = sign_eth(input.hmac_seed_id, input.path, input.msg_hash)
        elseif input.coin == "utxo" then
            response = sign_utxo(input.hmac_seed_id, input.path, input.msg_hash)
        else
            return { error = "unsupported coin " .. input.coin }
        end
        response.coin = input.coin

        return response
    end
