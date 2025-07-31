function check(input)
   if type(input) ~= 'table' then
      return nil, 'invalid input'
   end

   if input.subject_dn == nil then
      return nil, 'must provide subject DN'
   end

   if input.subject_key == nil then
      return nil, 'must specify subject key'
   end

   if input.attributes ~= nil and type(input.attributes) ~= 'table' then
      return nil, 'attributes must be a table'
   end

   if input.hash_alg ~= nil and type(input.hash_alg) ~= 'string' then
      return nil, 'digest must be a string'
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
      -- if there are multiple attributes in a Name,
      -- they will get overwritten in case of a dictionary.
      -- So, to allow specifying multiple attrs, we allow
      -- specifying a list of values instead of a single value.
      -- like "OU": ["OU1", "OU2"].
      if type(v) == 'table'
      then
         for _, v in ipairs(v)
         do
            name:set(Oid.from_str(k), v, 'utf8')
         end
      else
         name:set(Oid.from_str(k), v, 'utf8')
      end
   end

   return name
end

function add_san(csr_builder, critical, extension_info)
   local dns_names = extension_info.dns_names
   if type(dns_names) ~= 'table' then
      return nil, 'dns_names should be a list'
   end

   local der_encoded_value_builder = DerEncoder.new():start_seq()

   for _, dns_name in ipairs(dns_names)
   do
      der_encoded_value_builder = der_encoded_value_builder
         :implicit_context(2)
         :add_string(dns_name, 'ia5')
   end

   local ip_addresses = extension_info.ip_addresses
   if type(ip_addresses) ~= 'table' then
      return nil, 'ip_addresses should be a list'
   end

   for _, ip_address_str in ipairs(ip_addresses)
   do
      local ip_addr = IpAddr.new(ip_address_str)

      der_encoded_value_builder = der_encoded_value_builder
         :implicit_context(7)
         :add_octets(Blob.from_bytes(ip_addr:octets()))
   end

   local der_encoded_value = der_encoded_value_builder:end_seq():value()

   csr_builder:add_extension(Oid.from_str('subjectAlternativeName'), critical, der_encoded_value)
end

function add_csr_extension(csr_builder, extension, extension_info)
   if type(extension) ~= "string" then
      return nil, 'extension oid must be string'
   end

   if type(extension_info) ~= "table" then
      return nil, extension .. ' must be described with a table'
   end

   local critical = extension_info.critical

   if critical == nil then
      critical = false
   elseif type(critical) ~= 'boolean' then
      return nil, 'critical should be a bool'
   end

   if extension_info.der_value ~= nil then
      local der_value = Blob.from_base64(extension_info.der_value):bytes()
      csr_builder:add_extension(Oid.from_str(extension), critical, der_value)
   elseif extension == 'subjectAlternativeName' then
      add_san(csr_builder, critical, extension_info)
   else
      return nil, '`der_value` needed for ' .. extension
   end
end

function add_csr_attribute(csr_builder, attribute, attribute_info)
   if type(attribute) ~= "string" then
      return nil, 'attribute name must be string'
   end

   if type(attribute_info) ~= "table" then
       return nil, 'attribute info must be a table'
   end

   if attribute_info.der_values ~= nil then
      for _, der_value in ipairs(attribute_info.der_values) do
         local der_value = Blob.from_base64(der_value):bytes()
         csr_builder:append_attribute(Oid.from_str(attribute), der_value)
      end
   elseif attribute == 'extensionRequest' then
      for extension, extension_info in pairs(attribute_info) do
         add_csr_extension(csr_builder, extension, extension_info)
      end
   else
      return nil, '`der_values` needed for ' .. attribute
   end
end

function run(input)
   local subject_dn = load_dn(input.subject_dn)

   local csr_builder = Pkcs10Csr.builder()

   if input.hash_alg ~= nil then
      csr_builder:with_hash_alg(input.hash_alg)
   end

   csr_builder:with_subject(subject_dn)
   csr_builder:with_signer_sobject(input.subject_key)

   if input.attributes ~= nil then
      for attribute, attribute_info in pairs(input.attributes) do
         add_csr_attribute(csr_builder, attribute, attribute_info)
      end
   end

   local csr = csr_builder:build()

   return format_pem(Blob.from_bytes(csr:to_der()):base64(), "CERTIFICATE REQUEST")
end

