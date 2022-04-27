local service = ''
local region = ''
local debug = 'METHOD0'
local max_events_per_lookup = 500

function sign(key, msg) -- SHA256-HMAC
  assert(getmetatable(key) == Blob and type(msg) == 'string')
  
  local hmac_key = assert(Sobject.import { obj_type = 'HMAC', value = key, transient = true })
  return assert(hmac_key:mac { alg = 'SHA256', data = Blob.from_bytes(msg) }).digest
  end

function getSignatureKey(key, dateStamp, regionName, serviceName)
  assert(type(key) == 'string' and type(dateStamp) == 'string' and type(regionName) == 'string' and type(serviceName) == 'string')
  
  local kDate = sign(Blob.from_bytes('AWS4' .. key), dateStamp)
  local kRegion = sign(kDate, regionName)
  local kService = sign(kRegion, serviceName)
  return sign(kService, 'aws4_request')
end


function aws_request_v2(secret_id, amzTarget, request_body, method, args)
  local sobject, err = Sobject { id = secret_id }
  if sobject == nil or err ~= nil then
    err = "AWS credential is not configured or incorrect. Please run cofigure operation."
    return nil, err
  end
  if sobject.custom_metadata == nil then
    err = "AWS credential is not configured or incorrect. Kindly run cofigure operation."
    return nil, err
  end
  if sobject.custom_metadata["AccessKey"] == nil then
     err = "AWS credential is not configured or incorrect. Do run cofigure operation."
    return nil, err
  end
  local access_key = assert(sobject.custom_metadata['AccessKey'])
  local secret_key = assert(sobject:export().value:bytes())
  if service == nil or service == '' then service = assert(sobject.custom_metadata['Service']) end
  if region == nil  or region == ''  then region  = assert(sobject.custom_metadata['Region']) end
  local session_token = ''
  -- read the STS short-lived token, if any obtained from AssumeRole
  local session_created = sobject.custom_metadata["Session"]
  if session_created ~= nil then
    session_token = secret_key
    session_token = session_token:sub(41)
    secret_key = secret_key:sub(0, 40)
  end

  local host = service..'.'..region..'.amazonaws.com'
  local endpoint = 'https://'..host

  -- https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
  if service == "s3" then
    if args.bucket == nil or args.key == nil then
      return nil, "Invalid request to Amazon S3"
    end
    host = args.bucket ..'.'.. service..'.amazonaws.com'
    if args.key:sub(1, 1) ~= "/" then
      args.key = '/'.. args.key -- sanitize but don't normalize URI
    end
    endpoint = 'https://'..host..args.key
  end
  
  -- TBD get time object in DSM 4.x
  local amzdate = assert(Sobject.create { obj_type = 'AES', key_size = 128, transient = true }).created_at
  
  local datestamp = amzdate:sub(1, 8)
  local content_type = 'application/x-amz-json-1.1' -- all AWS APIs and if uploading JSON files as S3 objects
  local payload_hash = digest { alg = 'SHA256', data = Blob.from_bytes(request_body) }.digest:hex():lower()

  local canonical_uri = '/'
  local canonical_querystring = '' -- not needed for many AWS APIs or S3 PUT
  local canonical_headers = 'content-type:' .. content_type .. '\n' .. 'host:' .. host .. '\n'
  local signed_headers = 'content-type;host;'
  if service == "s3" then
    canonical_uri = args.key
    -- https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
    canonical_headers = canonical_headers .. 'x-amz-content-sha256:' .. payload_hash .. '\n'..
      'x-amz-date:' .. amzdate .. '\n'
    signed_headers = signed_headers .. 'x-amz-content-sha256;x-amz-date'
  else
    canonical_headers = canonical_headers .. 'x-amz-date:' .. amzdate .. '\n' ..
      'x-amz-target:' .. amzTarget .. '\n'
    signed_headers = signed_headers .. 'x-amz-date;x-amz-target'
  end

  if session_token ~= nil and session_token ~= "" then
    canonical_headers = canonical_headers ..'x-amz-security-token:' ..session_token ..'\n'
    signed_headers = signed_headers ..';x-amz-security-token'
  end

  local canonical_request = method .. '\n' .. canonical_uri .. '\n' .. canonical_querystring .. '\n' .. 
    canonical_headers .. '\n' .. signed_headers .. '\n' .. payload_hash
  
  local algorithm = 'AWS4-HMAC-SHA256'
  local credential_scope = datestamp .. '/' .. region .. '/' .. service .. '/' .. 'aws4_request'
  local string_to_sign = algorithm .. '\n' .. amzdate .. '\n' .. credential_scope .. '\n' .. 
    digest { alg = 'SHA256', data = Blob.from_bytes(canonical_request) }.digest:hex():lower()
  
  local signing_key = getSignatureKey(secret_key, datestamp, region, service)
  local signature = sign(signing_key, string_to_sign):hex():lower()
  
  local authorization_header = algorithm .. ' ' .. 'Credential=' .. access_key .. '/' .. 
    credential_scope .. ', ' .. 'SignedHeaders=' .. signed_headers .. ', ' .. 'Signature=' .. signature

  local request_url = endpoint 
  if canonical_querystring ~= "" then request_url = request_url .. '?' .. canonical_querystring end
  
  local headers = { ['X-Amz-Date'] = amzdate, ['Content-Type'] = content_type, ['Authorization'] = authorization_header}
  if service == "s3" then
    headers['x-amz-content-sha256'] = payload_hash
  else -- AWS API
    headers['X-Amz-Target'] = amzTarget
  end
  if session_token ~= nil and session_token ~= "" then
    headers['x-amz-security-token'] = session_token
  end
  
  local call_params = { method = method, url = request_url, headers = headers, body=request_body }
  if debug == 'REQ1' then return call_params end
  response, err = request(call_params)
  if debug == 'REQ2' then return response end

  if response == nil or err ~= nil then return err end
  if response.status >= 200 or response.status == 201 then
    if service == "s3" then return {key=endpoint} end
    return json.decode(response.body), err
  elseif response.status == 204 then
    return OK, nil -- does this apply?
  elseif response.status >= 400 then -- not allowed
    if response ~= nil then
      if response.body ~= nil then
        local err_message = json.decode(response.body)
        if err_message and err_message.value ~= nil then return nil, err_message.value
        else return err_message, nil end
        return response.body
      end
    end
  end
  return response, err
end


------

function list_aws_keys(secret_id)
  local apiTarget = "TrentService.ListKeys"
  local response, err = aws_request_v2(secret_id , apiTarget, "{}", "POST")
  if response ~= nil then
    return response, nil
  end
  if debug == "KEYS1" then return response end
  
  lookupFilters = {}
  for k,v in pairs(response.Keys) do
    cloudtrailevent = json.decode(v.CloudTrailEvent)
    table.insert(events, cloudtrailevent.eventTime .. ',' .. v.EventName .. ',' .. v.Resources[1].ResourceName)
  end  
  return events
end


function list_aws_events(secret_id, attrib_keys, attrib_vals)
  local events = {}
  local nextPage = "START"
  local eventCount = max_events_per_lookup
  
  while eventCount >= 0 do
    local request_body = {MaxResults = 50} -- max 50, paginate with response.NextToken
    if attrib_keys ~= nil and attrib_keys ~= nil then
      if type(attrib_keys) == "string" and  type(attrib_vals) == "string" then
        request_body["LookupAttributes"] = {{AttributeKey=attrib_keys, AttributeValue = attrib_vals}} -- array
      else
        request_body["LookupAttributes"] = {}
        for iter, attrkey in pairs(attrib_keys) do
          table.insert(request_body["LookupAttributes"], 
            {AttributeKey=attrkey, AttributeValue = attrib_vals[iter]} ) -- array
        end
      end
    end
    if nextPage ~= "START" then request_body["NextToken"] = nextPage end
    
    -- https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupAttribute.html
    if debug == "LOG1" then return request_body end
    local apiTarget = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents"
    local response, err = aws_request_v2(secret_id, apiTarget, json.encode(request_body), "POST")

    if response == nil then
      return response, err
    end
    if debug == "LOG2" then return response end -- quit after first page
    nextPage = response.NextToken

    -- https://docs.aws.amazon.com/kms/latest/developerguide/understanding-kms-entries.html
    if response.Events ~= nil then
      eventCount = eventCount - #response.Events
      for k,outerEvent in pairs(response.Events) do
        innerEvent = json.decode(outerEvent.CloudTrailEvent)
        if innerEvent.resources then -- filtering by key operation vs. impertinent ops like list/lookup etc.
            local event = { ts = outerEvent.EventTime, 
              when = innerEvent.eventTime, 
              what = innerEvent.eventName}
          if innerEvent.userIdentity then
            if innerEvent.userIdentity.type ~= nil then event.who = innerEvent.userIdentity.type .. " <" end
            if innerEvent.userIdentity.accountId ~= nil then event.who = event.who .. innerEvent.userIdentity.accountId end
            if innerEvent.userIdentity.userName ~= nil then event.who = event.who .. " ".. innerEvent.userIdentity.userName end
            if innerEvent.userIdentity.accessKeyId ~= nil then event.who = event.who .. " ".. innerEvent.userIdentity.accessKeyId end
            if innerEvent.userIdentity.invokedBy ~= nil then event.who = event.who .. innerEvent.userIdentity.invokedBy end
            if type(event.who) == "string" then
              event.who = event.who  ..">"
            else
              event.who = innerEvent.userIdentity
            end
          else
            event.who = outerEvent.Username
          end
          if #outerEvent.Resources > 0 then
            event.target = outerEvent.Resources[1].ResourceName
          else
            event.target = innerEvent.resources[1].ARN
          end
          table.insert(events, event)
        else
          if debug == "LOG3" then table.insert(events, outerEvent) end
        end -- if innerEvent.resources
      end -- for events loop
    end -- if events
  end -- pagination
  return events
end


function list_dsm_keys_events(filter, return_type)
  local return_obj = {}
  local sobjects, error = Sobject.get_all { }
  if debug == "DSM1" then return sobjects end
  for iter, sobj in pairs(sobjects) do
    if sobj.external and sobj.external.id and sobj.external.id.key_arn then
      if filter == nil or filter == sobj.kid or filter == sobj.name then
        if return_type == "KEYS" then
          table.insert(return_obj, sobj)
        else -- if return_type == EVENTS
          local dsm_events = AuditLog.get_all {object_id = sobj.kid}
          if debug == "DSM2" then return dsm_events end

          if dsm_events.hits and #dsm_events.hits > 0 then
            for iter, log in pairs(dsm_events.hits) do
              local log_time = assert(Time.from_iso8601(
                  log._source.time:gsub("-",""):gsub(":","") )):unix_epoch_seconds()

              table.insert(return_obj, {what = log._source.message, 
                  target = log._source.action_type.."/"..log._source.object_id, 
                  who = log._source.actor_type .. " <".. log._source.actor_id ..">", 
                  ts = log_time, when = log._source.time, source = "fortanix-dsm"} )
            end -- loop events
          end -- if key has events
        end -- if return_type == KEYS/EVENTS
      end -- if filtering keys
    end -- if AWS key through CDC
  end -- loop keys
  
  return return_obj
end


function merge_events(secret_id, descending)
  local merged_events = list_dsm_keys_events("", "EVENTS")
  if debug == "MERG1" then return merged_events end

  -- no direct way to ask for CloudTrail events related to just one key, 
  -- so get all events related to the KMS for now, possibly narrower with another filter
  local aws_events = list_aws_events(secret_id, "EventSource", "kms.amazonaws.com") 
  for iter, log in ipairs(aws_events) do
    if debug == "MERG2" then return log end
    log.source = "aws-cloudtrail"
    table.insert(merged_events, log)
  end
  
  if descending then table.sort(merged_events, function(a,b) return a.ts > b.ts end)
  else table.sort(merged_events, function(a,b) return a.ts < b.ts end) end
  
  return merged_events
end


function upload_to_s3(secret_id, events, bucket, key)
  service = "s3"
  if debug == "UPLD1" then return events end
  if debug == "UPLD2" then debug = "REQ1" end
  if debug == "UPLD3" then debug = "REQ2" end
  key = key .. "-" ..Time.now_insecure():unix_epoch_seconds()..".json"
 
  local response, err = aws_request_v2(secret_id, "", json.encode(events), "PUT", {bucket=bucket,key=key})
  if err ~= nil then return err end
  return response
end



----------------------------- ##### -----------------------------

function check(input)
  if input.debug ~= "" then debug = input.debug end
  if input.secret_id ~= nil then
    local secret, err = Sobject { id = input.secret_id }
    if secret == nil then return nil, 'Plugin needs a valid secret_id' end
    if secret.custom_metadata ~= nil then
      service = secret.custom_metadata['Service']
      region  = secret.custom_metadata['Region']
      if input.service == nil then input.service = service end
      if input.region  == nil then input.region  = region end
    end
  else
    if input.operation ~= "configure" and
      input.operation ~= "list-dsm-keys" and 
        input.operation ~= "list-dsm-events" then
      return nil, 'Plugin needs a secret_id to operate'
    else
      if input.service == nil then service = 'cloudtrail' end
      if input.region == nil then region = 'us-west-1' end
    end
  end
end

function run(input)
  if input.operation == "configure" then
    local name = Blob.random { bits = 64 }:hex()
    if input.service ~= '' and type(input.service) == 'string' then service = input.service end
    if input.region ~= '' and type(input.region) == 'string' then region = input.region end
    local is_session = nil
    if input.session_token and type(input.session_token) == 'string' and input.session_token ~= "" then
      is_session = "1"
    end
    
    if input.session_token == nil then input.session_token = "" end
    local secret = assert(Sobject.import{ name = name, obj_type = "SECRET", 
        value = Blob.from_bytes(input.secret_key .. input.session_token), 
        custom_metadata = { ["AccessKey"] = input.access_key, 
          ["Service"] = service, ["Region"] = region, 
          ["Session"] = is_session }
      })
    return {secret_id = secret.kid}

  elseif input.operation == "list-dsm-keys" then
    keys, err = list_dsm_keys_events(input.key, 'KEYS')
    return keys, err

  elseif input.operation == "list-dsm-events" then
    events, err = list_dsm_keys_events(input.key, 'EVENTS')
    return events, err

  elseif input.operation == "list-aws-keys" then
    service = 'kms'
    keys, err = list_aws_keys(input.secret_id)
    return keys, err

  elseif input.operation == "list-aws-events" then
    service = 'cloudtrail'
    events, err = list_aws_events(input.secret_id, input.lookup_attribkey, input.lookup_attribval)
    return events, err

  elseif input.operation == "merge-events" then
    events, err = merge_events(input.secret_id, input.revchrono)
    return events, err

  elseif input.operation == "upload-events" then
    events, err = merge_events(input.secret_id, input.revchrono)
    if err == nil then
      result, err = upload_to_s3(input.secret_id, events, input.bucket, input.object_key)
      return result, err
    else
      return err
    end

  else
    return nil, "Invalid operation"
  end
end


