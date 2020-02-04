-- Name: SSH CA
-- Version: 1.0
-- Description:## Short Description
-- Issue certificates for SSH authentication
--
-- ### ## Introduction
-- SSH certificates are a method for authenticating users and/or servers in the SSH protocol.
-- Instead of bare public keys (the usual method of SSH authentication) an authority
-- issues a certificate which can then be used to authenticate to an SSH server.
-- SSH certificates were originally added to OpenSSH in version 5.6 (released in 2010).
-- 
-- ## Use Cases
-- 
-- Authenticate clients to servers or servers to clients using an trusted third party
-- hosted on SDKMS.
-- 
-- ## Setup
-- 
-- ### Creating CA key with SDKMS
-- 
-- The initial step is to create a key for the SSH CA. Generate an RSA
-- key with suitable parameters on SDKMS, and then download the public key.
-- 
-- Converting the public to the OpenSSH format requires a two-step process.
-- First, use OpenSSL to convert the RSA key to "RSAPublicKey" format:
-- 
-- `$ openssl rsa -pubin -RSAPublicKey_out -in sdkms_rsa.pub > sdkms_rsa_conv.pem`
-- 
-- Then use `ssh-keygen` to convert this to the SSH format
-- 
-- `$ ssh-keygen -m PEM -i -f sdkms_rsa_conv.pem > ssh_ca.pub`
-- 
-- ### Creating CA key with OpenSSH
-- 
-- Alternatively, the key can be created on a trusted machine using OpenSSH
-- tools, then transferred to SDKMS:
-- 
-- `$ ssh-keygen -f ssh_ca`
-- 
-- This will create two files, `ssh_ca.pub` (public key in SSH format)
-- and `ssh_ca` (private key in PKCS #8 format).
-- 
-- ```
-- -----BEGIN RSA PRIVATE KEY-----
-- MIIEpAI...
-- -----END RSA PRIVATE KEY-----
-- ```
-- 
-- To import the SSH private key in SDKMS, copy the base64 encoded block
-- (but *not* the PEM headers starting with "-----") and paste it into
-- the Security Object import field. Make sure Sign and Verify operations
-- are enabled. Disable Export unless required.
-- 
-- ### Server Configuration
-- 
-- Set up sshd configuration for accepting SSH certificates. In your `sshd_config` add
-- 
-- `TrustedUserCAKeys /path/to/ssh_ca.pub`
-- 
-- and restart `sshd`
-- 
-- ### Issue Client Cert
-- 
-- Generate an RSA key pair that the user will use:
-- 
-- `ssh-keygen -f ~/.ssh/user_key`
-- 
-- This will again generate two keys, `user_key` (PKCS#8 private key) and
-- `user_key.pub` (the SSH format public key). The `user_key.pub` should look like
-- 
-- `ssh-rsa AAAAB3<more base64 data> username@hostname`
-- 
-- ## Input/Output JSON
-- 
-- ```
-- {
-- "cert_lifetime":<integer>,
-- "valid_principals":"<username>",
-- "cert_type":"user",
-- "ca_key":"<sobject name>",
-- "extensions":{<map of strings to strings>},
-- "critical_extensions":{<map of strings to strings>},
-- "pubkey":"<string>"
-- }
-- ```
-- 
-- "`cert_lifetime`" specifies the lifetime of the certificate in seconds.
-- 
-- "`valid_principals`" specifies what username this certificate can be used for.
-- 
-- "`cert_type`" can be "user" or "server".
-- 
-- "`ca_key`" gives the name of the private key that was used when the RSA key was
-- imported into SDKMS earlier.
-- 
-- "`extensions`" specifies operations the certificate can be used for. Values
-- OpenSSH supports include "`permit-X11-forwarding`", "`permit-agent-forwarding`"
-- "`permit-port-forwarding`", "`permit-pty`", and "`permit-user-rc`". In theory,
-- extensions can take values, but all currently defined extensions use an empty
-- string. Unknown values will be ignored by the server.
-- 
-- "`critical_extensions`" specifies operations which if the server does not
-- understand the value, then the login attempt will be rejected. The values OpenSSH
-- supports are "`force-command`" and "`source-address`". "`force-command`" specifies a
-- single command which the certificate can be used for. "`source-address`" gives a
-- list of host/mask pairs, login is only allowed from an IP matching one of the
-- listed values.
-- 
-- "`pubkey`" gives the contents of the `user_key.pub` file with the leading "`ssh-rsa `" and
-- trailing "` username@hostname`" removed.
-- 
-- ## Example Usage
-- 
-- ```
-- {
-- "cert_lifetime":86400,
-- "valid_principals":"desired_username",
-- "cert_type":"user",
-- "ca_key":"SSH CA Key",
-- "extensions":{"permit-pty":""},
-- "critical_extensions":{"source-address":"10.2.0.0/16,127.0.0.1"},
-- "pubkey":"AAAAB3<more base64 data>"}
-- }
-- ```
-- 
-- When the plugin is invoked it will return a string that looks like
-- 
-- `"ssh-rsa-cert-v01@openssh.com AAAAHHNza...."`
-- 
-- Copy the entire contents to `~/.ssh/user_key-cert.pub`
-- 
-- Now test the output using `ssh-keygen`:
-- 
-- ```
-- $ ssh-keygen -L  -f user_key-cert.pub
-- user_key-cert.pub:
--         Type: ssh-rsa-cert-v01@openssh.com user certificate
-- ...
-- ```
-- 
-- Now run
-- 
-- `$ ssh -i ~/.ssh/user_key server_host whoami`
-- 
-- The login should succeed with the command executed on the remote host.
-- 
-- If you use `-v` option when using a certificate you should see something like
-- 
-- ```
-- debug1: Offering public key: RSA-CERT SHA256:Hcb9trzeAptUdTgqWj9VEncbkAGOpAglGnUrYGq4/Vo user_key
-- debug1: Server accepts key: pkalg ssh-rsa-cert-v01@openssh.com blen 1029
-- ```
-- 
-- ## References
-- 
-- https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
-- 
-- ### Release Notes
-- 
-- Initial release

function getCaKeyType()
   --- FIXME type of signature key is hardcoded
   return "ssh-rsa"
end

--- utility function uuid ---
--- it will return an uuid ---
local function uuid()
   local template ='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
   return string.gsub(template, '[xy]', function (c)
                         local v = (c == 'x') and math.random(0, 0xf) or math.random(8, 0xb)
                         return string.format('%x', v)
   end)
end

function parse_ssh_pubkey(pkey_b64)
   local data = Blob.from_base64(pkey_b64):bytes()

   local pos = 1
   key_type, pos = string.unpack(">s4", data, pos)

   if key_type == "ssh-rsa"
   then
      exp, pos = string.unpack(">s4", data, pos)
      modulus, pos = string.unpack(">s4", data, pos)
      if pos ~= (#data) + 1
      then
         return nil, "invalid ssh-rsa key"
      end
      return key_type, modulus, exp
   else
      return nil, "unknown key type"
   end
end


--- key type ---
--- TODO need to support DSA, ECDSA, Ed25519
function getCertKeyType(key_type)
   if key_type == "ssh-rsa" then
      return 'ssh-rsa-cert-v01@openssh.com'
   end
   error('Only RSA keys are currently supported, no support for ' .. key_type)
end

---certificate type ---
--- 1. user ---
--- 2. host ---
function getCertType(req)
   if req.cert_type == 'user' then
      return 1
   end
   if req.cert_type == 'host' then
      return 2
   end
end

--- valid-principals ---
--- user-name for user ---
--- host-name for host ---
function getValidPrincipal(req)
   return string.pack(">s4", req.valid_principals)
end

--- format an integer in ssh format ---
function formatMPI(n)
   local n_bytes = n:to_bytes_be()
   local first_byte = n_bytes:slice(0,1):bytes()
   if (string.byte(first_byte) & 0x80) ~= 0
   then
      zp = Blob.from_hex("00") .. n_bytes
      return string.pack(">s4", zp:bytes())
   end
   return string.pack(">s4", n_bytes:bytes())
end

--- ca public key ---
function getSignaturePublicKey(ca_key)
   local ca_key = assert(Sobject { name = ca_key })
   local key_info = ca_key:rsa_public_info()
   return string.pack(">s4", "ssh-rsa") .. formatMPI(key_info.public_exponent) .. formatMPI(key_info.public_modulus)
end

function formatExtensions(extensions)
   local s = ''

   -- Extensions must be sorted by key
   local tkeys = {}
   for k in pairs(extensions) do
      table.insert(tkeys, k)
   end
   table.sort(tkeys)
   for _, k in ipairs(tkeys) do
      s = s .. string.pack('>s4', k)
      local value = extensions[k]
      if value == '' then
         s = s .. string.pack('>s4', '')
      else
         s = s .. string.pack('>s4', string.pack('>s4', value))
      end
   end
   return s
end

--- serialized req and ca components ---
function createCertData(req)
   key_type, modulus, exp = parse_ssh_pubkey(req.pubkey)

   local now = Time.now_insecure()

   local ca_pubkey = getSignaturePublicKey(req.ca_key)

   local cert_type = getCertKeyType(key_type)
   local nonce = Blob.random(12):base64()
   local created = now:unix_epoch_seconds()
   local expires = created + req.cert_lifetime
   local random_key_id = uuid()
   local critical_options = formatExtensions(req.critical_extensions)
   local extensions = formatExtensions(req.extensions)
   local reserved = ''
   local serial = now:unix_epoch_nanoseconds()

   rsa_cert_serialization = string.pack(">s4>s4>s4>s4>I8>I4>s4>s4>I8>I8>s4>s4>s4>s4",
                                        cert_type, nonce, exp, modulus,
                                        serial, getCertType(req), random_key_id, getValidPrincipal(req),
                                        created, expires,
                                        critical_options, extensions, reserved, ca_pubkey)
   return cert_type, rsa_cert_serialization
end

--- sign the give key ---
function signCertificate(ca_key, serialized_input)
   local ca_key = assert(Sobject { name = ca_key })
   local blob = Blob.from_bytes(serialized_input)
   local res, err = ca_key:sign {
      hash_alg = 'SHA1',
      data = blob,
   }
   assert(res, "Error performing signing : " .. tostring(err))
   return res
end

--- validate the input components ---
function check(req)
   if type(req) ~= 'table' then
      return nil, 'invalid req'
   end
   if not req.pubkey then
      return nil, 'must provide public key'
   end
   if not req.valid_principals then
      return nil, 'valid principals must be specified'
   end
   if req.cert_type ~= 'user' and req.cert_type ~= 'host' then
      return nil, 'invalid cert type'
   end
   if type(req.ca_key) ~= 'string' then
      return nil, 'must specify name of CA key'
   end
end

function run(req)
   cert_type, cert_data = createCertData(req)
   signature = signCertificate(req.ca_key, cert_data).signature
   signature_hdr = string.pack(">s4>I4", getCaKeyType(req), #signature:bytes())
   signature_w_hdr = Blob.from_bytes(string.pack(">I4", #signature_hdr + #signature:bytes())) .. Blob.from_bytes(signature_hdr) .. signature
   cert = Blob.from_bytes(cert_data) .. signature_w_hdr
   return cert_type .. " " .. cert:base64() .. " " .. req.valid_principals
end
