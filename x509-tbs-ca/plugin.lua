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

   local serial_number_bits = 160
   local new_cert = tbs:sign(issuer_cert, input.issuer_key, serial_number_bits, "SHA256")
   return format_pem(new_cert:export().value:base64(), "CERTIFICATE")
end
