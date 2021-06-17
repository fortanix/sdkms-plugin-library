-- Name: ServiceNow KEK Generate and Wrap Plugin
-- Version: 1.0
-- Description:## Short Description
-- This plugin will create KEK if it does not exist and returns wrapped KEK for ServiceNow.
-- ### ## Introduction
--
-- This plugin implements a service that can act as Customer Endpoint for Database Encryption Customer Controller Switch (DBE CCS) in ServiceNow. It securely generates a KEK for customer and wraps it with the supplied certificate. ServiceNow will call the service endpoint to get customer's wrappped KEK, unwrap it and use it for database encryption.
--
-- ## Header
--
-- Expects following in header
--
-- * X-DB-Certificate - base64 encoded x509 certificate that will be used to wrap KEK
--
-- ## URL for invocation
--
-- URL for invocation of this plugin is designed to match ServiceNow gateway's expectation. Plugin expects URL path to be on following format
--
-- https://SDKMS_SERVER_URL/sys/v1/plugins/invoke/{PLUGIN_ID}/kek/{instance}/{version}
--
-- Where
-- * version: KEK version. This is an integer.
-- * instance : ServiceNow instance name. This is an alpha-numeric string.
--
-- ## Input/Output JSON Object Format
--
-- Plugin does not need any input data.
--
-- Output:
--
-- Returns wrapped KEK as a JSON object in ServiceNow expected format.
-- ```
-- {
--    "keyId":1,
--     "wrappedKey":"MDsFvB8........nziVTy2og5B4QVBw9lcA==",
--     "validUntil":"2021-12-31T00:00:00Z"
-- }
-- ```
-- ## Reference
--
-- https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0789788
--
-- ### Release Notes
-- - Initial Release

function run(input, url, method, headers)
   local instance_name = url.path[7]
   if instance_name == nil then
      if not input.instance then
         return nil, 'instance name is missing in URL and request body'
      else
         instance_name = input.instance
      end
   end
   local key_version = url.path[8]
   if not key_version then
      if not input.version then
         return nil, 'key version is missing in URL and request body'
      else
         key_version = input.version
      end
   end
   local input_cert = headers["x-db-certificate"]
   if not input_cert then
      return nil, 'must specify certificate in header using x-db-certificate'
   end

   -- Check if ServiceNow root cert exists, if not import it
   local root_cert, error = Sobject { name = "servicenow_root_cert" }
   if root_cert == nil and error.status == 404 then
      local snow_root_cert = "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"
      root_cert = assert(Sobject.import { name = "servicenow_root_cert",
                                          obj_type = "CERTIFICATE",
                                          value = snow_root_cert})
   else
      if root_cert == nil and error.status ~= 404 then
         return nil, 'Could not detemine if ServiceNow root certificate exists'
      end
   end

   -- Import cert as transient object - it will be used as wrapping key
   local wrapping_key = assert(Sobject.import { obj_type = "CERTIFICATE",
                                                transient = true,
                                                value = input_cert})

   -- Validate CN in certificate with the instance name
   local cert_dn = wrapping_key:subject_dn()
   local cert_cn = cert_dn:get(Oid.from_str('CN'))

   if cert_cn ~= "tse_" .. instance_name then
      return nil, 'instance name does not match CN in certificate'
   end

   -- Validate Cert is issued by ServiceNow root cert
   if wrapping_key:verify_certificate(root_cert) ~= true then
      return nil, 'The certificate is not issued by the ServiceNow certificate authority'
   end

   -- If the KEK does not exist then create one
   local kek_name = "SN-KEK_" .. key_version
   local kek = Sobject { name = kek_name }

   if kek == nil then
      local key_ops = {"ENCRYPT","DECRYPT","WRAPKEY", "UNWRAPKEY", "APPMANAGEABLE","EXPORT"}
      kek = assert(Sobject.create { name = kek_name,
                                    obj_type = "AES",
                                    key_size = 256,
                                    key_ops = key_ops})
   end

   local wrapped_kek =  assert(wrapping_key:wrap { subject = kek, alg = "RSA", mode = "OAEP_MGF1_SHA1" })

   -- validUntil is currently set for 24 hours. This could be made configurable
   -- Format needs to be "2021-12-31T00:00:00Z"
   local tnow = wrapping_key.created_at
   local valid_year = tnow.sub(tnow, 1, 4)
   local valid_month = tnow.sub(tnow, 5, 6)
   local valid_day = tonumber(tnow.sub(tnow, 7, 8)) + 1
   local valid_hour = tnow.sub(tnow, 10, 11)
   local valid_minute = tnow.sub(tnow, 12, 13)
   local valid_second = tnow.sub(tnow, 14, 15)
   local valid_until = valid_year .. "-" .. valid_month .. "-" .. valid_day .. "T" .. valid_hour .. ":" .. valid_minute .. ":" .. valid_second .. "Z"

   return {keyId = tonumber(key_version), wrappedKey = wrapped_kek.wrapped_key, validUntil = valid_until }
end
