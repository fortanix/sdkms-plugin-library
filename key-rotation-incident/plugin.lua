local _endpoint = 'dev.service-now.com'
local _content_type = 'application/json'
local _schedule = 365
local _tag = "ftnxreminder"
local _message = "This is a reminder to rotate the following key"
local _params = "number,short_description,opened_at,urgency"
local _method = "/api/now/v1/table/incident"

-- Input validation function --
function check(input)
  local metadata = {}

  if input.secret_id ~= nil then
    local secret, err = Sobject { id = input.secret_id }
    if secret == nil then return nil, 'Plugin needs a valid secret_id' end
    if secret.custom_metadata ~= nil then
      if secret.custom_metadata['Endpoint'] ~= nil then
        _endpoint = secret.custom_metadata['Endpoint']
      end
      if secret.custom_metadata['Schedule'] ~= nil then
        _schedule = assert(tonumber(secret.custom_metadata['Schedule']))
      end
      if secret.custom_metadata['Tag'] ~= nil then
        _tag = secret.custom_metadata['Tag']
      end
      if secret.custom_metadata['Message'] ~= nil then
        _message = secret.custom_metadata['Message']
      end
      metadata = secret.custom_metadata
    end
    metadata["Endpoint"] = _endpoint
    metadata["Tag"] = _tag
    metadata["Schedule"] = tostring(_schedule)
    metadata["Message"] = _message
    metadata["Params"] = _params
    assert(secret:update{custom_metadata = metadata} )

  else
    if input.operation ~= "configure" and
      input.operation ~= "list-keys" then
      return nil, 'Plugin needs a secret_id to operate'
    else
      if input.operation == "configure" and
        input.endpoint == nil then
        return 400, "Invalid Service-Now endpoint"
      end
    end
  end
  if input.filter ~= nil then
    if input.filter:find(",") then
      input.filter = input.filter:gsub("%s+", "")
      local _filter = {}
      for token in input.filter:gmatch("[^,]+") do
        _filter[token] = 1
      end
      input.filter = _filter
    end
  else
    input.filter = {AES=1,RSA=1,EC=1}
  end
  if input.endpoint == nil or input.endpoint == '' then 
    input.endpoint = _endpoint
  end
  if input.schedule == nil then
    input.schedule = _schedule
  end
  if input.tag == nil then
    input.tag = _tag
  end
  if input.message == nil then
    input.message = _message
  end
  if input.params == nil then
    input.params = _params
  end
end

-- ServiceNow helper function --
function svcnow_request(secret_id, api_target, request_body, method)

  local sobject, err = assert(Sobject { id = secret_id })
  local secret_key = sobject:export().value:bytes()

  local request_url = 'https://'.. _endpoint ..'/'.. api_target
  local headers = { 
    ['Content-Type'] = content_type,
    ['Authorization'] = 'Basic ' .. secret_key
  }
  
  local args = { method = method, url = request_url, headers = headers, body=request_body }
  response, err = request(args)
  if response == nil or err ~= nil then return err end
  if response.error ~= nil then return response.error end
  if response.status == 200 or response.status == 201 then -- GET or POST
    if response.headers and response.headers["content-type"] ~= nil and 
      (response.headers["content-type"] == _content_type or
      response.headers["content-type"] == _content_type..";charset=UTF-8") then
      
      local content = assert(json.decode(response.body))
      if content.result ~= nil then return content.result end
      return content
    else
      if response.body then
        return json.encode(response.body)
      else
        return nil, json.encode(response)
      end
    end
  elseif response.status > 201 and response.status < 300 then
    return nil, "Response not recognized" -- response
  elseif response.status >= 400 then -- not allowed
    if response ~= nil and response.body ~= nil then
        local err_message = assert(json.decode(response.body))
        if err_message.value ~= nil then return nil, err_message.value end
        return err_message
    end
  end
  return nil, "Unknown error"
end

function run(input)
  if input.operation == "configure" then
    local name = Blob.random { bits = 64 }:hex()
    if input.endpoint ~= '' and type(input.endpoint) == 'string' then
      endpoint = input.endpoint
    end
    if input.api_key == nil then
      if input.username ~= nil and input.password ~= nil then
        input.api_key = Blob.from_bytes(input.username.. ':'..
          input.password):base64()
      else
        return nil, "Invalid credentials"
      end
    end
    local secret = assert(Sobject.import{ name = name, obj_type = "SECRET", 
        value = Blob.from_bytes(input.api_key ), 
        custom_metadata = { ["Endpoint"] = endpoint, 
          ["Schedule"] = tostring(input.schedule),
          ["Tag"] = tostring(input.tag),
          ["Params"] = tostring(input.params),
          ["Message"] = tostring(input.message) }
      })
    return {secret_id = secret.kid}

  elseif input.operation == "list-incidents" then

    return svcnow_request(input.secret_id, 
      _method.."?work_notes="..input.tag.."&"..
      "sysparm_fields=".. input.params, "", "GET")
    
  elseif input.operation == "list-keys" or
    input.operation == "notify-incidents" then
    local pg_start = 0
    local pg_limit = 100
    local sobjs, error
    local keys_expiring = {}

    repeat
      sobjs, error = Sobject.get_all { offset=pg_start, limit=pg_limit }

      local threshold = input.schedule*24*60*60
      local period = 30*24*60*60
      local t90 = threshold-3*period
      local t60 = threshold-2*period
      local t30 = threshold-1*period

      local ts_now = Time.now_insecure():unix_epoch_seconds()

      for k, key in pairs(sobjs) do

        if input.filter == nil or key.obj_type == input.filter or
          input.filter[key.obj_type] then
          
          if keys_expiring[key.group_id] == nil then
            keys_expiring[key.group_id] = {}
          end
          local key_created = Time.from_iso8601(key.created_at):unix_epoch_seconds()
          local delta = ts_now - key_created

          local to_notify = 0
          if (key.links ~= nil and key.links.replacement == nil) or 
             key.links == nil then -- not rotated
            
            if delta > threshold then
              to_notify = 99
            elseif delta == threshold then
              to_notify = 4
            elseif delta < threshold and delta > t30 then
              to_notify = 3
            elseif delta <= t30 and delta > t60 then
              to_notify = 2
            elseif delta <= t60 and delta >= t90 then
              to_notify = 1
            end
            
            if to_notify > 0 and to_notify < 5 then

              if key.custom_metadata == nil or key.custom_metadata[input.attribute] == nil then
                table.insert(keys_expiring[key.group_id],
                  { created=key.created_at, key=key.name, type=key.obj_type,
                    notify=to_notify, meta=key.custom_metadata } )
              end
              if input.operation ~= "list-keys"  and
                ( input.notify_again == true or key.custom_metadata == nil or
                  key.custom_metadata[input.tag..tostring(to_notify).."-incident"] == nil ) then

                local req_body = {}
                if input.notify ~= nil then
                  req_body = input.notify
                end
                req_body["work_notes"]="FORTANIX "..input.tag.." Key ID: "..key.kid..
                  " from Group ID: "..key.group_id.." was created on "..key.created_at
                req_body["short_description"]=input.message..": "..key.name..
                  " #"..input.tag..tostring(to_notify)
                req_body["urgency"]=to_notify
                req_body["notify"]=1
                local resp, err = svcnow_request(input.secret_id, 
                  _method, json.encode(req_body), "POST")
                if resp == nil then
                  return err
                else
                  attrib = key.custom_metadata
                  if attrib == nil then attrib = {} end
                  attrib[input.tag..tostring(to_notify)] = Time.now_insecure():to_iso8601()
                  if resp.number ~= nil then
                    attrib[input.tag..tostring(to_notify).."-incident"] = resp.number
                  end
                  assert(key:update{custom_metadata = attrib} )
                end

              end -- if notify_always or key_metada not found with Number
            end -- if to_notify valid            
          end -- if key replacement doesn't exist i.e. not rotated
        end -- if filter/none
      end -- for sobjs across groups

      if pg_limit == #sobjs then
        pg_start = pg_start + pg_limit
      end
    until ( sobjs and #sobjs < pg_limit ) -- pagination

    return keys_expiring
  
  end -- operation switch
end -- run
