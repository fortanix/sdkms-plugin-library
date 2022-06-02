----------------- Constant --------------------
local CONSENSUS_KEY =  "consensus-key"


-- BlockID is complete
function is_complete(b)
  if string.len(b.hash) == 64 and b.part_set_header.total > 0 and string.len(b.part_set_header.hash) == 64 then return true end
  return false
end

-- BlockID is zero
function is_zero(b)
  if (b == null) then return true end
  return false
end

-- Proposal is valid and there is no double signing
function proposal_is_valid(p)
  local key = assert(Sobject { name = CONSENSUS_KEY })
  local s = key.custom_metadata
  local s_height = tonumber(s.height)
  local s_round = tonumber(s.round)
  if p.req_type == 32 and p.height > 0 and p.round >= 0 and is_complete(p.block_id) then
	-- Double-sign prevention: A signer should only sign a proposal p if any of the following conditions are true:
    if p.height > s_height then return true end
    if p.height == s_height and p.round > s_round then return true end
  end
  return false
end

-- Vote is valid and there is no double signing
function vote_is_valid(v)
  local key = assert(Sobject { name = CONSENSUS_KEY })
  local s = key.custom_metadata
  local s_height = tonumber(s.height)
  local s_round = tonumber(s.round)
  if v.req_type == 1 or v.req_type == 2 then
  	if v.height > 0 and v.round >= 0 then
      if is_zero(v.block_id) or is_complete(v.block_id) then
          -- Double-sign prevention: A signer should only sign a vote v if any of the following lines are true:
          if v.height > s_height then return true end
          if v.height == s_height and v.round > s_round then return true end
          if v.height == s_height and v.round == s_round and v.req_type == 1 and s.req_type == "32" then return true end
          if v.height == s_height and v.round == s_round and v.req_type == 2 and s.req_type ~= "2" then return true end
      end
    end
  end
  return false
end

-- The input is the same as the last one.
function is_same(input)
  local key = assert(Sobject { name = CONSENSUS_KEY })
  local s = key.custom_metadata
  local s_height = tonumber(s.height)
  local s_round = tonumber(s.round)
  if tonumber(s.req_type) == input.req_type and s_height == input.height and s_round == input.round and s.last_data == input.data then
    return true
  end
  return false
end


function sign(input)
  local key = assert(Sobject { name = CONSENSUS_KEY })

  if not input.data then return Error.new {status = 400, message = 'missing field `data`', signature = ''} end

  local sign_response, error = key:sign { data = input.data, hash_alg = 'SHA512', deterministic_signature = true }
  if error ~= nil then
    	return Error.new {
            status = 500,
            message = 'Sign Error - ' .. tostring(error)
        }
  end
  _, err1 = key:update { custom_metadata = { round = tostring(input.round), height = tostring(input.height), req_type = tostring(input.req_type), last_data = tostring(input.data) } }
  if err1 ~= nil then return nil, err1 end

  return { status = 200, signature = sign_response.signature}
end

local function has_fields(dict, keys)
    for _, key in pairs(keys) do
        if not dict[key] then
      		return key .. ' not found'
        end
    end
    return nil
end

function run(input)

  	local err = has_fields(input, {"data", "block_id", "req_type", "height", "round"})
  	if err then return Error.new {status = 400, message = err} end

    if not (input.block_id == null) then
      local err = has_fields(input.block_id, {"hash", "part_set_header"})
  	  if err then return Error.new {status = 400, message = err} end
      local err = has_fields(input.block_id.part_set_header, {"hash", "total"})
  	  if err then return Error.new {status = 400, message = err} end
    end

   -- Validate that the req_type is either 1, 2 or 32. 1: Prevote, 2: Precommit, 32: Proposal
   if input.req_type ~= 1 and input.req_type ~= 2 and input.req_type ~= 32 then return nil, 'invalid req_type' end
   -- Look up the signing key
   local key = assert(Sobject { name = CONSENSUS_KEY })

  	if input.req_type == 1 and vote_is_valid(input) == true then return sign(input) end
    if input.req_type == 2 and vote_is_valid(input) == true then return sign(input) end
    if input.req_type == 32 and proposal_is_valid(input) == true then return sign(input) end
  	if is_same(input) == true then return sign(input) end

    return Error.new {
          status = 500,
          message = 'Double sign prevented.'
    }

end