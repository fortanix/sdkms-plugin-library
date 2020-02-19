-- Name: X.509 TBS CA
-- Version: 1.0
-- Description:## Short Description
-- Creates a signed X.509 Certificate structure for keys managed by SDKMS. It showcases the flexibility of the plugin framework to use user-specific data formats.
--
-- ### ## Introduction 
-- X.509 certificates are a key element of many security architectures. It cryptographically ties a public key to the issuer of the certificate. Companies may wish to use their own input format.
-- This example plugin shows the flexibility of Fortanix's plugin framework. In this case a basic JSON structure is accepted as input. After the input passes a user-specified verification function, any desired fields can be added and a valid X509 certificate is created. The signed certificate is returned  in PEM format.
-- 
-- ## Use Cases
-- 
-- X.509 certificates are used in a wide variety of applications:
-- 
--  - Webservers use X.509 certificates as part of TLS to authenticate their identity
--  - IPsec uses it to authenticate peers
--  - Code signing systems such as Microsoft Authenticate enable verification of vendors of computer programs
-- 
-- ## Input/Output JSON Object Format
-- 
-- The input is a JSON map with the following fields:
-- 
-- * `subject_key`: the name of the key that will be included in the certificate
-- * `issuer_cert`: the name of the issuer cert stored in SDKMS
-- * `issuer_key`: the name of the issuer key stored in SDKMS
-- * `cert_lifetime`: the lifetime of the certificate in seconds
-- * `subject_dn`: a map of OIDs to values
-- 
-- ## Example Usages
-- 
-- ```
-- {
--   "issuer_cert": "my CA cert",
--   "issuer_key": "my CA key",
--   "subject_key": "my server key",
--   "cert_lifetime": 86400,
--   "subject_dn": { "CN": "localhost", "OU": "Testing" }
-- }
-- ```
-- 
-- ## References
-- 
--  - https://www.rfc-editor.org/rfc/rfc5280.txt
-- 
-- ### Release Notes 
--  - Initial release

function check(input)
   if type(input) ~= 'table' then
      return nil, 'invalid input'
   end
   if not input.subject_dn then
      return nil, 'must provide subject DN'
   end
   if not input.subject_key then
      return nil, 'must provide subject key'
   end
   if not input.issuer_key then
      return nil, 'must specify issuing key'
   end
   if not input.issuer_cert then
      return nil, 'must specify issuing cert'
   end
   if not input.cert_lifetime then
      return nil, 'must specify certificate lifetime'
   end
end

function format_pem(b64, type)
   local wrap_at = 64
   local len = string.len(b64)
   local pem = ""

   pem = pem .. "-----BEGIN " .. type .. "-----\n"

   for i = 1, len, wrap_at do
      local stop = i + wrap_at - 1
      pem = pem .. string.sub(b64, i, stop) .. "\n"
   end

   pem = pem .. "-----END " .. type .. "-----\n"

   return pem
end

function load_dn(dn)
   local name = X509Name.new()

   for k,v in pairs(dn)
   do
      name:set(Oid.from_str(k), v, 'utf8')
   end

   return name
end

function run(input)
   local issuer_key = assert(Sobject { name = input.issuer_key })
   local issuer_cert = assert(Sobject { name = input.issuer_cert })

   local subject_dn = load_dn(input.subject_dn)
   -- log the DN here?

   local skid = Blob.random(12):base64()

   local tbs = TbsCertificate.new(input.subject_key, subject_dn, skid, input.cert_lifetime)

   local bc = DerEncoder.new():start_seq():add_bool(false):end_seq():value()
   tbs:add_extension(Oid.from_str('basicConstraints'), true, bc)

   local cert_policy = DerEncoder.new():start_seq()
      :start_seq():add_oid(Oid.from_str("1.2.3.4")):end_seq()
      :end_seq():value()
   tbs:add_extension(Oid.from_str('2.5.29.32'), false, cert_policy)

   local new_cert = tbs:sign(issuer_cert, input.issuer_key, input.cert_lifetime)
   return format_pem(new_cert:export().value:base64(), "CERTIFICATE")
end

