--Safenet library, another secure modem messages library
--By Rami Sabbagh (RamiLego4Game)

--== Embedded libraries ==--

--A SHA-256 library, returns a hex string, from http://www.computercraft.info/forums2/index.php?/topic/8169-sha-256-in-pure-lua/
local sha256 = loadstring("local a=2^32;local b=a-1;local function c(d)local e={}local f=setmetatable({},e)function e:__index(g)local h=d(g)f[g]=h;return h end;return f end;local function i(f,j)local function k(l,m)local n,o=0,1;while l~=0 and m~=0 do local p,q=l%j,m%j;n=n+f[p][q]*o;l=(l-p)/j;m=(m-q)/j;o=o*j end;n=n+(l+m)*o;return n end;return k end;local function r(f)local s=i(f,2^1)local t=c(function(l)return c(function(m)return s(l,m)end)end)return i(t,2^(f.n or 1))end;local u=r({[0]={[0]=0,[1]=1},[1]={[0]=1,[1]=0},n=4})local function v(l,m,w,...)local x=nil;if m then l=l%a;m=m%a;x=u(l,m)if w then x=v(x,w,...)end;return x elseif l then return l%a else return 0 end end;local function y(l,m,w,...)local x;if m then l=l%a;m=m%a;x=(l+m-u(l,m))/2;if w then x=bit32_band(x,w,...)end;return x elseif l then return l%a else return b end end;local function z(A)return(-1-A)%a end;local function B(l,C)if C<0 then return lshift(l,-C)end;return math.floor(l%2^32/2^C)end;local function D(A,C)if C>31 or C<-31 then return 0 end;return B(A%a,C)end;local function lshift(l,C)if C<0 then return D(l,-C)end;return l*2^C%2^32 end;local function E(A,C)A=A%a;C=C%32;local F=y(A,2^C-1)return D(A,C)+lshift(F,32-C)end;local g={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2}local function G(H)return string.gsub(H,\".\",function(w)return string.format(\"%02x\",string.byte(w))end)end;local function I(J,K)local H=\"\"for L=1,K do local M=J%256;H=string.char(M)..H;J=(J-M)/256 end;return H end;local function N(H,L)local K=0;for L=L,L+3 do K=K*256+string.byte(H,L)end;return K end;local function O(P,Q)local R=64-(Q+9)%64;Q=I(8*Q,8)P=P..\"\\128\"..string.rep(\"\\0\",R)..Q;assert(#P%64==0)return P end;local function S(T)T[1]=0x6a09e667;T[2]=0xbb67ae85;T[3]=0x3c6ef372;T[4]=0xa54ff53a;T[5]=0x510e527f;T[6]=0x9b05688c;T[7]=0x1f83d9ab;T[8]=0x5be0cd19;return T end;local function U(P,L,T)local V={}for W=1,16 do V[W]=N(P,L+(W-1)*4)end;for W=17,64 do local h=V[W-15]local X=v(E(h,7),E(h,18),D(h,3))h=V[W-2]V[W]=V[W-16]+X+V[W-7]+v(E(h,17),E(h,19),D(h,10))end;local l,m,w,Y,Z,d,_,a0=T[1],T[2],T[3],T[4],T[5],T[6],T[7],T[8]for L=1,64 do local X=v(E(l,2),E(l,13),E(l,22))local a1=v(y(l,m),y(l,w),y(m,w))local a2=X+a1;local a3=v(E(Z,6),E(Z,11),E(Z,25))local a4=v(y(Z,d),y(z(Z),_))local a5=a0+a3+a4+g[L]+V[L]a0,_,d,Z,Y,w,m,l=_,d,Z,Y+a5,w,m,l,a5+a2 end;T[1]=y(T[1]+l)T[2]=y(T[2]+m)T[3]=y(T[3]+w)T[4]=y(T[4]+Y)T[5]=y(T[5]+Z)T[6]=y(T[6]+d)T[7]=y(T[7]+_)T[8]=y(T[8]+a0)end;local function a6(P)P=O(P,#P)local T=S({})for L=1,#P,64 do U(P,L,T)end;return G(I(T[1],4)..I(T[2],4)..I(T[3],4)..I(T[4],4)..I(T[5],4)..I(T[6],4)..I(T[7],4)..I(T[8],4))end;return a6")()
--A md5 library, modified to use CC bit library, from 
local md5 = loadstring("local a={}local b,c,d,e,f=string.char,string.byte,string.format,string.rep,string.sub;local g,h,i,j,k,l;do local function m(n)local o=0;local p=1;for q=1,#n do o=o+n[q]*p;p=p*2 end;return o end;local function r(s,t)local u,v=s,t;if#u<#v then u,v=v,u end;for q=#v+1,#u do v[q]=0 end end;local w;i=bit.bnot;w=function(x)if x<0 then return w(i(math.abs(x))+1)end;local n={}local y=1;local z;while x>0 do z=x%2;n[y]=z;x=(x-z)/2;y=y+1 end;return n end;g=bit.bor;h=bit.band;j=bit.bxor;k=bit.brshift;l=bit.blshift end;local function A(q)local B=function(C)return b(h(k(q,C),255))end;return B(0)..B(8)..B(16)..B(24)end;local function D(C)local E=0;for q=1,#C do E=E*256+c(C,q)end;return E end;local function F(C)local E=0;for q=#C,1,-1 do E=E*256+c(C,q)end;return E end;local function G(C,...)local H,I=1,{}local J={...}for q=1,#J do table.insert(I,F(f(C,H,H+J[q]-1)))H=H+J[q]end;return I end;local K=function(L)return D(A(L))end;local M={0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391,0x67452301,0xefcdab89,0x98badcfe,0x10325476}local B=function(N,O,P)return g(h(N,O),h(-N-1,P))end;local Q=function(N,O,P)return g(h(N,P),h(O,-P-1))end;local R=function(N,O,P)return j(N,j(O,P))end;local q=function(N,O,P)return j(O,g(N,-P-1))end;local P=function(S,T,U,V,W,N,C,X)T=h(T+S(U,V,W)+N+X,0xFFFFFFFF)return g(l(h(T,k(0xFFFFFFFF,C)),C),k(T,32-C))+U end;local function Y(Z,_,a0,a1,a2)local T,U,V,W=Z,_,a0,a1;local a3=M;T=P(B,T,U,V,W,a2[0],7,a3[1])W=P(B,W,T,U,V,a2[1],12,a3[2])V=P(B,V,W,T,U,a2[2],17,a3[3])U=P(B,U,V,W,T,a2[3],22,a3[4])T=P(B,T,U,V,W,a2[4],7,a3[5])W=P(B,W,T,U,V,a2[5],12,a3[6])V=P(B,V,W,T,U,a2[6],17,a3[7])U=P(B,U,V,W,T,a2[7],22,a3[8])T=P(B,T,U,V,W,a2[8],7,a3[9])W=P(B,W,T,U,V,a2[9],12,a3[10])V=P(B,V,W,T,U,a2[10],17,a3[11])U=P(B,U,V,W,T,a2[11],22,a3[12])T=P(B,T,U,V,W,a2[12],7,a3[13])W=P(B,W,T,U,V,a2[13],12,a3[14])V=P(B,V,W,T,U,a2[14],17,a3[15])U=P(B,U,V,W,T,a2[15],22,a3[16])T=P(Q,T,U,V,W,a2[1],5,a3[17])W=P(Q,W,T,U,V,a2[6],9,a3[18])V=P(Q,V,W,T,U,a2[11],14,a3[19])U=P(Q,U,V,W,T,a2[0],20,a3[20])T=P(Q,T,U,V,W,a2[5],5,a3[21])W=P(Q,W,T,U,V,a2[10],9,a3[22])V=P(Q,V,W,T,U,a2[15],14,a3[23])U=P(Q,U,V,W,T,a2[4],20,a3[24])T=P(Q,T,U,V,W,a2[9],5,a3[25])W=P(Q,W,T,U,V,a2[14],9,a3[26])V=P(Q,V,W,T,U,a2[3],14,a3[27])U=P(Q,U,V,W,T,a2[8],20,a3[28])T=P(Q,T,U,V,W,a2[13],5,a3[29])W=P(Q,W,T,U,V,a2[2],9,a3[30])V=P(Q,V,W,T,U,a2[7],14,a3[31])U=P(Q,U,V,W,T,a2[12],20,a3[32])T=P(R,T,U,V,W,a2[5],4,a3[33])W=P(R,W,T,U,V,a2[8],11,a3[34])V=P(R,V,W,T,U,a2[11],16,a3[35])U=P(R,U,V,W,T,a2[14],23,a3[36])T=P(R,T,U,V,W,a2[1],4,a3[37])W=P(R,W,T,U,V,a2[4],11,a3[38])V=P(R,V,W,T,U,a2[7],16,a3[39])U=P(R,U,V,W,T,a2[10],23,a3[40])T=P(R,T,U,V,W,a2[13],4,a3[41])W=P(R,W,T,U,V,a2[0],11,a3[42])V=P(R,V,W,T,U,a2[3],16,a3[43])U=P(R,U,V,W,T,a2[6],23,a3[44])T=P(R,T,U,V,W,a2[9],4,a3[45])W=P(R,W,T,U,V,a2[12],11,a3[46])V=P(R,V,W,T,U,a2[15],16,a3[47])U=P(R,U,V,W,T,a2[2],23,a3[48])T=P(q,T,U,V,W,a2[0],6,a3[49])W=P(q,W,T,U,V,a2[7],10,a3[50])V=P(q,V,W,T,U,a2[14],15,a3[51])U=P(q,U,V,W,T,a2[5],21,a3[52])T=P(q,T,U,V,W,a2[12],6,a3[53])W=P(q,W,T,U,V,a2[3],10,a3[54])V=P(q,V,W,T,U,a2[10],15,a3[55])U=P(q,U,V,W,T,a2[1],21,a3[56])T=P(q,T,U,V,W,a2[8],6,a3[57])W=P(q,W,T,U,V,a2[15],10,a3[58])V=P(q,V,W,T,U,a2[6],15,a3[59])U=P(q,U,V,W,T,a2[13],21,a3[60])T=P(q,T,U,V,W,a2[4],6,a3[61])W=P(q,W,T,U,V,a2[11],10,a3[62])V=P(q,V,W,T,U,a2[2],15,a3[63])U=P(q,U,V,W,T,a2[9],21,a3[64])return h(Z+T,0xFFFFFFFF),h(_+U,0xFFFFFFFF),h(a0+V,0xFFFFFFFF),h(a1+W,0xFFFFFFFF)end;local function a4(self,C)self.pos=self.pos+#C;C=self.buf..C;for a5=1,#C-63,64 do local a2=G(f(C,a5,a5+63),4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4)assert(#a2==16)a2[0]=table.remove(a2,1)self.a,self.b,self.c,self.d=Y(self.a,self.b,self.c,self.d,a2)end;self.buf=f(C,math.floor(#C/64)*64+1,#C)return self end;local function a6(self)local a7=self.pos;local a8=56-a7%64;if a7%64>56 then a8=a8+64 end;if a8==0 then a8=64 end;local C=b(128)..e(b(0),a8-1)..A(h(8*a7,0xFFFFFFFF))..A(math.floor(a7/0x20000000))a4(self,C)assert(self.pos%64==0)return A(self.a)..A(self.b)..A(self.c)..A(self.d)end;function a.new()return{a=M[65],b=M[66],c=M[67],d=M[68],pos=0,buf='',update=a4,finish=a6}end;function a.tohex(C)return d(\"%08x%08x%08x%08x\",D(f(C,1,4)),D(f(C,5,8)),D(f(C,9,12)),D(f(C,13,16)))end;function a.sum(C)return a.new():update(C):finish()end;function a.sumhexa(C)return a.tohex(a.sum(C))end;return a")()

--== CC modules ==--
local expect = dofile("rom/modules/main/cc/expect.lua").expect

--== Static Variables ==--
local chunkSize = 64
local maxChunks = 21
local timePrecision = 0.015
local computerID = os.getComputerID()
local consumedTerminatingChunks = {} --Stores the last chunk, which must be a part of the decrypted post salt, until the keys change, so messages replay attack won't work :-)

--== Internal functions ==--

--Converts a hex string into a binary string
local function hex2bin(hex)
	return hex:gsub("%x%x",function(subHex) return string.char(tonumber(subHex,16)) end)
end

--Converts an unsigned integer into a binary string of 4 bytes
local function int2bin(num)
	return string.char(bit.band(num,255), bit.band(bit.brshift(num,8),255), bit.band(bit.brshift(num,16),255), bit.band(bit.brshift(num,44),255) )
end

--Converts a binary string of 4 bytes into an unsigned integer
local function bin2int(bin)
	return string.byte(bin,1) + bit.blshift(string.byte(bin,2),8) + bit.blshift(string.byte(bin,3),16) + bit.blshift(string.byte(bin,4),24)
end

--Returns an integer, based on os.time(), changes every n seconds
local function getTime()
	return math.floor(os.time() / timePrecision)
end

--Returns a string with random bytes.
local function makeSalt(length)
	local characters = {}
	for i=1, length do
		characters[i] = string.char(math.random(0,255))
	end
	return table.concat(characters)
end

--Returns an xor encryption key for a given time, secret and (optional) previous (decrypted) chunk
local function calculateKey(id, secret, time, previousChunk)
	return hex2bin(sha256( id..secret..time..(previousChunk or "") ))
end

--Returns the channel id from a key, bust be 2 bytes long or more
local function getChannelID(key)
	return string.byte(key,1) + bit.blshift(string.byte(key,2),8)
end

--Encrypts/Decrypts data using XOR
local function XOR(key,data)
	local keyLength, keyPosition = #key, 0
	
	--Convert the key into a table of bytes numbers
	local keyBytes = {}
	for i=1, keyLength do
		keyBytes[i] = string.byte(key,i)
	end
	
	local resultChars = {}
	for i=1, #data do
		resultChars[i] = string.char(bit.bxor(string.byte(data,i), keyBytes[keyPosition+1]))
		keyPosition = (keyPosition + 1) % keyLength
	end
	
	return table.concat(resultChars)
end

--Decodes a secure message
local function decodeMessage(message, secret, time, lastChunk)
	if #message < 8+8+16 or (#message % chunkSize > 0) then return false, "Invalid message length" end
	if #message > chunkSize*maxChunks then return false, "Too long message" end
	
	local decryptedChunks = {}
	for i=1, #message, chunkSize do
		local chunkKey = calculateKey(computerID, secret, time, lastChunk)
		local chunk = message:sub(i,i + chunkSize -1)
		local decryptedChunk = XOR(chunkKey, chunk)
		decryptedChunks[#decryptedChunks + 1] = decryptedChunk
		lastChunk = decryptedChunk
	end
	
	local decryptedMessage = table.concat(decryptedChunks)
	local preSaltLength = bin2int(decryptedMessage:sub(1,4))
	local postSaltLength = bin2int(decryptedMessage:sub(5,8))
	
	if (#decryptedMessage - (preSaltLength + postSaltLength)) < 16 then return false, "Invalid salts lengths" end
	
	local recordedMd5 = decryptedMessage:sub(4+4+1, 4+4+16)
	local content = decryptedMessage:sub(4+4+16+preSaltLength+1,-postSaltLength-1)
	
	local actualMd5 = md5.sum(decryptedMessage:sub(4+4+16+1,-1))
	if recordedMd5 ~= actualMd5 then return false, "Unmatching md5 checksum" end
	
	return true, content, lastChunk
end

--Encodes a secure message
local function encodeMessage(message, receiverID, secret, time, lastChunk)
	local preSaltLength = math.random(chunkSize,chunkSize*2)
	local postSaltLength = math.random(chunkSize,chunkSize*2)
	
	--Align for complete chunks of encoded message
	local currentLength = (4 + 4 + preSaltLength + 16 + #message + postSaltLength)
	postSaltLength = postSaltLength + (math.ceil(currentLength/chunkSize)*chunkSize - currentLength)
	
	--Generate the salts
	local preSalt = makeSalt(preSaltLength)
	local postSalt = makeSalt(postSaltLength)
	
	--Calculate the md5
	local dataMd5 = md5.sum(preSalt..message..postSalt)
	
	--Construct the message
	local decryptedMessage = table.concat({int2bin(preSaltLength), int2bin(postSaltLength), dataMd5, preSalt, message, postSalt})
	
	--Encrypt the message
	local encryptedChunks = {}
	for i=1, #decryptedMessage, chunkSize do
		local chunkKey = calculateKey(receiverID, secret, time, lastChunk)
		local chunk = decryptedMessage:sub(i,i+chunkSize-1)
		local encryptedChunk = XOR(chunkKey, chunk)
		encryptedChunks[#encryptedChunks + 1] = encryptedChunk
		lastChunk = chunk
	end
	
	local encryptedMessage = table.concat(encryptedChunks)
	
	return encryptedMessage, lastChunk
end

--== Encryption API ==--

--for usage in other modem libraries, like rednet...

--Encrypts a message
--Returns false, reason, on failure !
--Returns true, encryptedMessage on success
function encryptMessage(message, targetID, secret)
	expect(1, message, "string")
	expect(2, targetID, "number")
	expect(3, secret, "string")
	
	if #message > chunkSize*(maxChunks-5) then return false, "The message is too long, it could be "..((maxChunks-6)*chunkSize).." bytes maximum!" end
	return true, (encodeMessage(message, targetID, secret, getTime()))
end

--Decrypts a message
--Returns false, reason, on failure !
--Otherwise return true, decrypted message and lastDecryptedChunk (Used for defending against message replay).
function decryptMessage(message, targetID, secret)
	expect(1, message, "string")
	expect(2, targetID, "number")
	expect(3, secret, "string")
	
	return decodeMessage(message, targetID, secret, getTime())
end

--Returns the remaining time (in seconds) for the next key time, used to make sure that the encrypted message don't get expired on it's way
function timeUntilNewKeys()
	local time = os.time() / timePrecision
	return (time - math.floor(time))*timePrecision*100
end

--== Safenet API ==--
--Inspired by rednet API

local channelUpdateTime = (getTime() + 1)*timePrecision
local channelUpdateAlarm = os.setAlarm(channelUpdateTime)
local keepAliveTimer = os.startTimer(timePrecision*200)
local activeModems = {}

--Opens a modem for secure communication
function open(sModem, secret)
	expect(1,sModem,"string")
	expect(2,secret,"string")
	
	if peripheral.getType(sModem) ~= "modem" then
		return error("No such modem: "..sModem)
	end
	
	local modem = peripheral.wrap(sModem)
	local channel = getChannelID(calculateKey(computerID, secret, getTime()))
	activeModems[sModem] = {
		modem = modem,
		channel = channel,
		secret = secret
	}
end

--Closes a modem
function close(sModem)
	expect(1,sModem,"string")
	if sModem then
		--Close a specific modem
		if activeModems[sModem] then
			local info = activeModems[sModem]
			info.modem.close(info.channel)
			activeModems[sModem] = nil
		end
	else
		--Close all modems
		for sModem, info in pairs(activeModems) do
			info.modem.close(info.channel)
			activeModems[sModem] = nil
		end
	end
end

--Checks if a modem is open in safenet
function isOpen(sModem)
	expect(1,sModem,"string","nil")
	
	if sModem then
		--Return if that modem is open
		if activeModems[sModem] then return true end
	else
		--Return if any modem is open
		for k,v in pairs(activeModems) do
			if v then return true end
		end
	end
	
	return false
end

--Limits the distance of a modem
function limitDistance(sModem,limit)
	expect(1,sModem,"string")
	expect(2,limit,"number","nil")
	if not activeModems[sModem] then return error("This modem is not open by safenet!") end
	activeModems[sModem].distanceLimit = limit
end

--Disallow messages from other dimentions
function limitDimension(sModem,limit)
	expect(1,sModem,"string")
	if not activeModems[sModem] then return error("This modem is not open by safenet!") end
	activeModems[sModem].dimentionLimit = not not limit
end

--Send a message
function send(modemSide, receiverID, message, hideID, dirty)
	expect(1,modemSide,"string","nil")
	expect(2,receiverID,"number")
	expect(3,message,"string")
	expect(4,replySecret,"string","nil")
	
	if #message > chunkSize*(maxChunks-5) then return error("The message is too long, it could be "..((maxChunks-6)*chunkSize).." bytes maximum!") end
	
	if modemSide then
		if not activeModems[modemSide] then return error("This modem is not open by safenet!") end
		
		--Wait for the new key
		if not dirty then
			for event in pullEvent do if event == "safenet_new_keys" then break end end
		end
		
		local info = activeModems[modemSide]
		local messageTime = getTime()
		local encryptedMessage, lastChunk = encodeMessage(message, receiverID, info.secret, messageTime)
		local receiverChannel = getChannelID(calculateKey(receiverID, info.secret, messageTime))
		
		info.replyChunk = lastChunk --TODO: Open reply channel
		info.modem.transmit(receiverChannel, hideID and 65535 or computerID, encryptedMessage)
	else
		
		--Wait for the new key
		if not dirty then
			for event in pullEvent do if event == "safenet_new_keys" then break end end
		end
		
		--Send using all the safenet modems
		for side, info in pairs(activeModems) do
			if info then
				send(side, receiverID, message, hideID, true)
			end
		end
	end
end

--Receive a message
function receive(sModem, timeout)
	expect(1, sModem, "string", "nil")
	expect(2, timeout, "number", "nil")
	
	if sModem and not activeModems[sModem] then return error("This modem is not open by safenet!") end
	
	--Set the timeout timer
	if timeout then timeout = os.startTimer(timeout) end
	
	for event, modem_side, message, distance, senderID in pullEvent do
		if event == "safenet_message" then
			if not sModem or sModem == modem_side then
				return message, distance, senderID, modem_side
			end
		elseif event == "timer" and timeout and timeout == modem_side then
			return false
		end
	end
end

--Pass events into the library, for advanced users.
function eventPulled(event,a,b,c,d,e,f)
	
	if event == "modem_message" then
		local modemSide, senderChannel, replyChannel, message, distance = a,b,c,d,e
		
		--Is this a safenet modem ?
		if activeModems[modemSide] then
			local info = activeModems[modemSide]
			
			--Is it out of the limited distance
			if info.distanceLimit and distance > info.distanceLimit and distance ~= 0 then
				os.queueEvent("safenet_rejected", modemSide, "Too far for the soft-limited distance", senderChannel, replyChannel, message, distance)
			elseif info.dimensionLimit and distance == 0 then
				os.queueEvent("safenet_rejected", modemSide, "From other dimensions", senderChannel, replyChannel, message, distance)
			else
				--Is it a new message ?
				if senderChannel == info.channel then
				
					local valid, content, lastChunk = decodeMessage(message, info.secret, getTime())
					
					if valid then
						if consumedTerminatingChunks[lastChunk] then
							os.queueEvent("safenet_rejected", modemSide, "Replayed message", senderChannel, replyChannel, message, distance)
						else
							consumedTerminatingChunks[lastChunk] = true
							
							if replyChannel ~= 65535 then
								--Known sender
								os.queueEvent("safenet_message", modemSide, content, distance, replyChannel)
							else
								--Unkown sender
								os.queueEvent("safenet_message", modemSide, content, distance)
							end
						end
					else
						os.queueEvent("safenet_rejected", modemSide, content, senderChannel, replyChannel, message, distance)
					end
				end
			end
		end
		
	elseif (event == "alarm" and a == channelUpdateAlarm) or channelUpdateTime+timePrecision < os.time() or channelUpdateTime > os.time()+timePrecision then
		
		--Update the channels for all the active modems.
		os.queueEvent("safenet_new_keys")
		
		for sModem, info in pairs(activeModems) do
			info.modem.close(info.channel)
			info.channel = getChannelID(calculateKey(computerID, info.secret, getTime()))
			info.modem.open(info.channel)
		end
		
		--Set the new alarm
		channelUpdateTime = (getTime() + 1)*timePrecision
		channelUpdateAlarm = os.setAlarm(channelUpdateTime)
		
		--A timer for making sure alarms are set and running
		os.cancelTimer(keepAliveTimer)
		keepAliveTimer = os.startTimer(timePrecision*200)
		
		--Clear the consumed terminating chunks table
		consumedTerminatingChunks = {}
	end
end

--Pull events, required for receiving the librarie's events
function pullEvent(target)
	eventPulled("none") --To make sure alarms are set
	local event, a,b,c,d,e,f = os.pullEvent(target)
	eventPulled(event, a,b,c,d,e,f)
	return event,a,b,c,d,e,f
end

--Pull raw events, required for receiving the librarie's events
function pullEventRaw(target)
	eventPulled("none") --To make sure alarms are set
	local event, a,b,c,d,e,f = os.pullEventRaw(target)
	gotEvent(eventPulled, a,b,c,d,e,f)
	return event,a,b,c,d,e,f
end

--Runs the event loop, use only with the parallel API!
function run()
	while true do
		pullEventRaw()
	end
end
