-- Name: X.509 CA
-- Version: 1.0
-- Description:## Short Description
-- Issue X.509 certificates for keys stored in SDKMS.
--
-- ### ## Introduction
-- The X.509 CA plugin allows SDKMS users to issue certificates for keys stored in SDKMS.
-- The plugin requires the CA key and certificate to be stored in SDKMS as well.
-- 
-- Once invoked, the plugin generates an X.509 certificate and returns the new certificate in PEM format encoded as a JSON string. To invoke the plugin, the user must specify the following as input to the plugin:
-- 
-- - Subject's Distinguished Name (DN),
-- - The name of the issuer certificate stored in SDKMS,
-- - The name of the issuer key stored in SDKMS,
-- - The name of the subject key stored in SDKMS,
-- - The lifetime of the generated certificate in seconds.
-- 
-- The public key of the subject key will be included in the generated certificate.
-- The generated certificate will have a randomly generated serial number.
-- 
-- Note that this plugin does not add limiting extensions, such as the key usage extension, to the generated certificate. It also does not ensure that the generated certificate is acceptable for any particular use case. For example, it allows the user to generate a certificate for `CN=domain1.com` while the issuer certificate is for `CN=domain2.net` which may not be acceptable. For more information about X.509 certificates see [RFC 5280](#rfc5280).
-- 
-- Also note that this plugin does not store the generated certificate in SDKMS and does not track generated certificates in any way, therefore, it does not prevent issuance of multiple certificates for the same subject.
-- 
-- ## Setup
-- In order to use this plugin, you need to generate or import your CA key and certificate in SDKMS. Additionally, you need to generate/import the subject key for each certificate you like to generate using this plugin.
-- Note that the plugin needs to have access to these security objects in SDKMS. To ensure the plugin has access to these security objects, make sure that the plugin shares a group with each security object that it needs to access.
-- 
-- Here is an example arrangement of objects in SDKMS:
-- 
-- - Two groups: `X.509 CA` and `TLS Keys`,
-- - The CA certificate (`x509 CA cert`) and CA key (`x509 CA key`) residing in group `X.509 CA`,
-- - The subject key for an app that requires a certificate (`my app key`) residing in `TLS Keys`,
-- - The X.509 CA plugin residing in both groups.
-- 
-- The example usage section shows how to invoke the plugin using the above setup to generate a certificate.
-- 
-- ## Input/Output
-- 
-- This plugin accepts a JSON object with the following fields as input:
-- 
-- * `subject_dn`: a map of OIDs to values
-- * `issuer_cert`: the name of the issuer cert security object
-- * `issuer_key`: the name of the issuer key security object
-- * `subject_key`: the name of the subject key security object
-- * `cert_lifetime`: the lifetime of the certificate in seconds
-- 
-- It returns the newly generated certificate in PEM format encoded as a JSON string.
-- 
-- 
-- ## Example Usage
-- 
-- Assuming the necessary objects are created as described in the example in the setup section, we can generate a certificate for `my app key` by invoking the plugin with the following input:
-- 
-- ```json
-- {
--   "subject_dn": {
--     "CN": "localhost",
--     "OU": "Testing"
--   },
--   "subject_key": "my app key",
--   "issuer_key": "x509 CA key",
--   "issuer_cert": "x509 CA cert",
--   "cert_lifetime": 86400
-- }
-- ```
-- 
-- The value for `cert_lifetime` in the example above is 24 hours expressed in seconds.
-- 
-- 
-- ## References
-- - <a name="rfc5280"></a>[RFC 5280](https://tools.ietf.org/html/rfc5280)
-- 
-- 
-- ### Release Notes
-- - Initial release

function check(input)
   if type(input) ~= 'table' then
      return nil, 'invalid input'
   end
   if not input.subject_dn then
      return nil, 'must provide subject DN'
   end
   if not input.subject_key then
      return nil, 'must specify subject key'
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
   local subject_key = assert(Sobject { name = input.subject_key })
   local issuer_key = assert(Sobject { name = input.issuer_key })
   local issuer_cert = assert(Sobject { name = input.issuer_cert })

   local subject_dn = load_dn(input.subject_dn)
   -- log the DN here?

   local csr = Pkcs10Csr.new(input.subject_key, subject_dn)

   local new_cert = csr:sign(issuer_cert, input.issuer_key, input.cert_lifetime, input.digest)
   return format_pem(new_cert:export().value:base64(), "CERTIFICATE")
end
