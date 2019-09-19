--A script for testing safenet

--Reload safenet, for development reasons
if safenet then os.unloadAPI("safenet.lua") end

--Load safenet library
if not safenet then os.loadAPI("safenet.lua") end

--Encryption secret, must be the same on both sides for this to work
local secret = "haghuyjfguyhklhyjgiouhuodf54848954323214465249824dfpijhjhd368q489465a1dfraf84a984fw1352231321f98f49223efda4984d8a"

local modemSide = pocket and "back" or "top"

safenet.open(modemSide, secret)
print("Openned secure connection")

local preClock = os.clock()

if pocket then
	safenet.send(modemSide, 22, "PING")
	print("Sent initial PING")
end

local function loop()
	print("Started loop")
	for event, a,b,c,d,e,f in safenet.pullEvent do
		if event == "safenet_message" then
			local modem_side, message, distance, senderID = a,b,c,d
			
			if message == "PING" then
				print("Received PING, distance: "..distance..", sender: "..(senderID or "unknown"))
				if senderID then safenet.send(pocket and "back" or "top", senderID, "PONG") end
			elseif message == "PONG" then
				print("Received PONG, distance: "..distance..", sender: "..(senderID or "unknown"))
				local postClock = os.clock()
				print("Delta Time:",(postClock - preClock))
				preClock = postClock
				if senderID then safenet.send(pocket and "back" or "top", senderID, "PING", false, pocket) end
			end
		elseif event == "safenet_rejected" then
			local modem_side, reason, senderChannel, replyChannel, message, distance = a,b,c,d,e,f
			print("Rejected message, reason: "..reason..", from: "..replyChannel..", distance: "..distance)
		elseif event == "safenet_new_keys" then
			print("Got new keys")
		end
	end
end

local ok, err = pcall(loop)
safenet.close(modemSide)
assert(ok, err)
