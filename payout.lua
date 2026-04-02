local HttpService = game:GetService("HttpService")

-- custom function for base 64 encoding (so that we dont need outside depedencies)
local function base64_encode(data)
	local b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	return ((data:gsub(".", function(x)
		local r, b = "", x:byte()
		for i = 8, 1, -1 do r = r .. (b % 2^i - b % 2^(i-1) > 0 and "1" or "0") end
		return r
	end) .. "0000"):gsub("%d%d%d?%d?%d?%d?", function(x)
		if #x < 6 then return "" end
		local c = 0
		for i = 1, 6 do c = c + (x:sub(i,i) == "1" and 2^(6-i) or 0) end
		return b:sub(c+1, c+1)
	end) .. ({ "", "==", "=" })[#data % 3 + 1])
end

-- custom function for base 64 decoding (so that we dont need outside depedencies)
local function base64_decode(data)
	local b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	data = string.gsub(data, "[^" .. b .. "=]", "")
	return (data:gsub(".", function(x)
		if x == "=" then return "" end
		local r, f = "", (b:find(x) - 1)
		for i = 6, 1, -1 do r = r .. (f % 2^i - f % 2^(i-1) > 0 and "1" or "0") end
		return r
	end):gsub("%d%d%d?%d?%d?%d?%d?%d?", function(x)
		if #x ~= 8 then return "" end
		local c = 0
		for i = 1, 8 do c = c + (x:sub(i,i) == "1" and 2^(8-i) or 0) end
		return string.char(c)
	end))
end

-- custom function for base 32 decoding (so that we dont need outside depedencies)
local function base32_decode(str)
	local b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	local bits = ""
	local decoded = ""
	str = string.upper(str:gsub("=", ""))
	for i = 1, #str do
		local val = b32:find(str:sub(i,i)) - 1
		for j = 4, 0, -1 do
			bits = bits .. (bit32.band(bit32.rshift(val, j), 1))
		end
	end
	for i = 1, #bits - 7, 8 do
		decoded = decoded .. string.char(tonumber(bits:sub(i, i+7), 2))
	end
	return decoded
end

-- custom function for sha1 (so that we dont need outside depedencies)
local function sha1(msg)
	local function rol(v, s) return bit32.lshift(v, s) + bit32.rshift(v, 32 - s) end
	local h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
	local bits = #msg * 8
	msg = msg .. string.char(0x80)
	while #msg % 64 ~= 56 do msg = msg .. string.char(0) end
	msg = msg .. string.char(0,0,0,0) .. string.char(bit32.rshift(bits, 24), bit32.band(bit32.rshift(bits, 16), 0xFF), bit32.band(bit32.rshift(bits, 8), 0xFF), bit32.band(bits, 0xFF))

	for i = 1, #msg, 64 do
		local chunk = msg:sub(i, i + 63)
		local w = {}
		for j = 1, 16 do
			local a, b, c, d = chunk:byte(j*4-3, j*4)
			w[j] = bit32.lshift(a, 24) + bit32.lshift(b, 16) + bit32.lshift(c, 8) + d
		end
		for j = 17, 80 do w[j] = rol(bit32.bxor(w[j-3], w[j-8], w[j-14], w[j-16]), 1) end

		local a, b, c, d, e = h0, h1, h2, h3, h4
		for j = 1, 80 do
			local f, k
			if j <= 20 then f = bit32.bor(bit32.band(b, c), bit32.band(bit32.bnot(b), d)); k = 0x5A827999
			elseif j <= 40 then f = bit32.bxor(b, c, d); k = 0x6ED9EBA1
			elseif j <= 60 then f = bit32.bor(bit32.band(b, c), bit32.band(b, d), bit32.band(c, d)); k = 0x8F1BBCDC
			else f = bit32.bxor(b, c, d); k = 0xCA62C1D6 end

			local temp = bit32.lshift(a, 5) + bit32.rshift(a, 27) + f + e + k + w[j]
			e, d, c, b, a = d, c, rol(b, 30), a, bit32.band(temp, 0xFFFFFFFF)
		end
		h0 = bit32.band(h0 + a, 0xFFFFFFFF); h1 = bit32.band(h1 + b, 0xFFFFFFFF)
		h2 = bit32.band(h2 + c, 0xFFFFFFFF); h3 = bit32.band(h3 + d, 0xFFFFFFFF); h4 = bit32.band(h4 + e, 0xFFFFFFFF)
	end

	local function to_bytes(v)
		return string.char(bit32.band(bit32.rshift(v, 24), 0xFF), bit32.band(bit32.rshift(v, 16), 0xFF), bit32.band(bit32.rshift(v, 8), 0xFF), bit32.band(v, 0xFF))
	end
	return to_bytes(h0) .. to_bytes(h1) .. to_bytes(h2) .. to_bytes(h3) .. to_bytes(h4)
end

-- custom function for hmac (so that we dont need outside depedencies)
local function hmac_sha1(key, msg)
	if #key > 64 then key = sha1(key) end
	key = key .. string.rep(string.char(0), 64 - #key)
	local ipad, opad = "", ""
	for i = 1, 64 do
		ipad = ipad .. string.char(bit32.bxor(key:byte(i), 0x36))
		opad = opad .. string.char(bit32.bxor(key:byte(i), 0x5C))
	end
	return sha1(opad .. sha1(ipad .. msg))
end

-- custom function for generating totp (so that we dont need outside depedencies)
local function generate_totp(secret)
	local decoded_secret = base32_decode(secret)
	local current_time = math.floor(os.time() / 30)

	local time_bytes = ""
	for i = 7, 0, -1 do
		time_bytes = time_bytes .. string.char(bit32.band(bit32.rshift(current_time, i * 8), 0xFF))
	end

	local hash = hmac_sha1(decoded_secret, time_bytes)
	local offset = bit32.band(hash:byte(20), 0x0F)

	local value = bit32.bor(
		bit32.lshift(bit32.band(hash:byte(offset + 1), 0x7F), 24),
		bit32.lshift(bit32.band(hash:byte(offset + 2), 0xFF), 16),
		bit32.lshift(bit32.band(hash:byte(offset + 3), 0xFF), 8),
		bit32.band(hash:byte(offset + 4), 0xFF)
	)

	local code = tostring(value % 1000000)
	while #code < 6 do code = "0" .. code end
	return code
end


-- ACTUAL ROBLOX PAYOUT CLASS

local RobloxPayout = {}
RobloxPayout.__index = RobloxPayout

function RobloxPayout.new(roblosecurity, group_id, twofactor_secret, proxy_url)
	local self = setmetatable({}, RobloxPayout)
	self.roblosecurity = roblosecurity
	self.group_id = group_id
	self.twofactor_secret = twofactor_secret
	self.proxy_url = proxy_url or "roproxy.com"

	self.headers = {
		["Cookie"] = ".ROBLOSECURITY=" .. self.roblosecurity,
		["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) Gecko/20100101 Firefox/148.0",
		["Content-Type"] = "application/json"
	}

	return self
end

function RobloxPayout:_request(url, method, req_headers, body)
	local success, result = pcall(function()
		return HttpService:RequestAsync({
			Url = url,
			Method = method,
			Headers = req_headers,
			Body = body
		})
	end)
	return success and result or {StatusCode = 0, Headers = {}, Body = ""}
end

function RobloxPayout:_set_csrf()
	local req = self:_request("https://auth." .. self.proxy_url .. "/v2/logout", "POST", self.headers)

	if req.StatusCode == 401 then
		print("Incorrect roblosecurity")
		return false
	end

	local token = req.Headers["x-csrf-token"] or req.Headers["X-CSRF-TOKEN"]
	if token then
		self.headers["X-CSRF-TOKEN"] = token
	end
	return true
end

function RobloxPayout:_payout_request(user_id, robux_amount, extra_headers)
	local req_headers = {}
	for k, v in pairs(self.headers) do req_headers[k] = v end
	if extra_headers then
		for k, v in pairs(extra_headers) do req_headers[k] = v end
	end

	local body = HttpService:JSONEncode({
		PayoutType = 1,
		Recipients = {
			{
				amount = robux_amount,
				recipientId = user_id,
				recipientType = 0
			}
		}
	})

	return self:_request("https://groups." .. self.proxy_url .. "/v1/groups/" .. tostring(self.group_id) .. "/payouts", "POST", req_headers, body)
end

function RobloxPayout:_verify_request(sender_id, challenge_id)
	local body = HttpService:JSONEncode({
		actionType = "Generic",
		challengeId = challenge_id,
		code = generate_totp(self.twofactor_secret)
	})

	local req = self:_request("https://twostepverification." .. self.proxy_url .. "/v1/users/" .. tostring(sender_id) .. "/challenges/authenticator/verify", "POST", self.headers, body)

	if req.StatusCode == 0 then return nil end
	local req_json = HttpService:JSONDecode(req.Body)

	if req_json.errors then
		print("2fa error")
		print(req_json.errors[1].message)
		return nil
	end
	return req_json.verificationToken
end

function RobloxPayout:_continue_request(challenge_id, challenge_type, metadata)
	local body = HttpService:JSONEncode({
		challengeId = challenge_id,
		challengeType = challenge_type,
		challengeMetadata = HttpService:JSONEncode(metadata)
	})

	return self:_request("https://apis." .. self.proxy_url .. "/challenge/v1/continue", "POST", self.headers, body)
end

function RobloxPayout:payout(user_id, robux_amount)
	if not self:_set_csrf() then return false end

	print("Sending initial payout request...")
	local request = self:_payout_request(user_id, robux_amount)

	if request.StatusCode == 200 then
		print("Robux successfully sent! (No challenge required)")
		return true
	end

	local challenge_type = string.lower(request.Headers["rblx-challenge-type"] or request.Headers["Rblx-Challenge-Type"] or "")
	local challenge_id = request.Headers["rblx-challenge-id"] or request.Headers["Rblx-Challenge-Id"] or ""
	local challenge_metadata_b64 = request.Headers["rblx-challenge-metadata"] or request.Headers["Rblx-Challenge-Metadata"] or ""

	if challenge_type == "" or challenge_id == "" then
		print("Payout error - no challenge headers found")
		print(request.Body)
		return false
	end

	local final_req

	-- handle chef challenge
	if challenge_type == "chef" then
		print("chef challenge detected. Solving...")
		local chef_metadata_raw = base64_decode(challenge_metadata_b64)
		local chef_metadata = HttpService:JSONDecode(chef_metadata_raw)

		local continue_req = self:_continue_request(challenge_id, "chef", chef_metadata)
		local cont_data = HttpService:JSONDecode(continue_req.Body)

		local next_challenge_type = cont_data.challengeType or ""
		local next_metadata_raw = cont_data.challengeMetadata or ""

		if next_challenge_type == "" then
			print("chef passed without 2fa, retrying payout...")
			local retry_headers = {
				["rblx-challenge-id"] = challenge_id,
				["rblx-challenge-type"] = "twostepverification",
				["rblx-challenge-metadata"] = challenge_metadata_b64
			}
			final_req = self:_payout_request(user_id, robux_amount, retry_headers)

		elseif next_challenge_type == "twostepverification" then
			print("chef requires 2fa challenge...")
			local tfa_metadata = HttpService:JSONDecode(next_metadata_raw)
			local tfa_user = tfa_metadata.userId
			local tfa_cid = tfa_metadata.challengeId

			local vtoken = self:_verify_request(tfa_user, tfa_cid)
			if not vtoken then return false end

			tfa_metadata.verificationToken = vtoken
			tfa_metadata.rememberDevice = false
			self:_continue_request(challenge_id, "twostepverification", tfa_metadata)

			local tfa_proof_raw = HttpService:JSONEncode({
				rememberDevice = false,
				actionType = "Generic",
				verificationToken = vtoken,
				challengeId = tfa_cid
			})
			local tfa_proof = base64_encode(tfa_proof_raw)

			print("Retrying payout with 2fa proof...")
			local retry_headers = {
				["rblx-challenge-id"] = challenge_id,
				["rblx-challenge-type"] = "twostepverification",
				["rblx-challenge-metadata"] = tfa_proof
			}
			final_req = self:_payout_request(user_id, robux_amount, retry_headers)

			if final_req.StatusCode ~= 200 then
				print("First retry failed, trying alternative chef headers...")
				retry_headers["rblx-challenge-type"] = "chef"
				retry_headers["rblx-challenge-metadata"] = challenge_metadata_b64
				final_req = self:_payout_request(user_id, robux_amount, retry_headers)
			end

		elseif next_challenge_type == "blocksession" then
			print("Session flagged (AutomatedTampering). Wait a minute and try again.")
			return false
		else
			print("Unknown challenge:", next_challenge_type)
			return false
		end

		if final_req and final_req.StatusCode == 200 then
			print("Robux successfully sent after chef challenge!")
			return true
		else
			print("Payout error after chef challenge:")
			print(final_req and final_req.Body or "")
			return false
		end

		-- if chef is not required
	elseif challenge_type == "twostepverification" then
		print("No chef challenge, doing 2fa...")
		local metadata_raw = base64_decode(challenge_metadata_b64)
		local metadata = HttpService:JSONDecode(metadata_raw)
		local metadata_challenge_id = metadata.challengeId
		local sender_id = metadata.userId

		local verification_token = self:_verify_request(sender_id, metadata_challenge_id)
		if not verification_token then return false end

		local tfa_proof = {
			rememberDevice = false,
			actionType = "Generic",
			verificationToken = verification_token,
			challengeId = metadata_challenge_id
		}

		self:_continue_request(challenge_id, "twostepverification", tfa_proof)

		local retry_headers = {
			["rblx-challenge-id"] = challenge_id,
			["rblx-challenge-metadata"] = base64_encode(HttpService:JSONEncode(tfa_proof)),
			["rblx-challenge-type"] = "twostepverification"
		}

		final_req = self:_payout_request(user_id, robux_amount, retry_headers)
		if final_req.StatusCode == 200 then
			print("Robux successfully sent after 2fa!")
			return true
		else
			print("Payout error after 2fa:")
			print(final_req.Body)
			return false
		end

	elseif challenge_type == "blocksession" then
		print("Session temporarily flagged on first request. Wait a minute and try again.")
		return false
	else
		print("Unknown challenge type:", challenge_type)
		return false
	end
end

return RobloxPayout