function to_binary(arg)
	-- convert a string to binary array
	-- return a table
	-- for example:
	--  to_binary("abc")
	--  => {97, 98, 99}
	--
	--  to_binary("\x01\x02\x03")
	--  => {1, 2, 3}
	--
	local t = {}
	for i = 1, #arg do
		t[i] = string.byte(arg, i)
	end
	return t
end

function on_packet(eth_frame)
	local ip = eth_frame:ipv4()
	if ip == nil then
		return
	end
	
	local tcp = ip:tcp()
	if tcp == nil then
		return
	end

	--										  PUSH+ACK
	if tcp:src_port() == 80 and tcp:flags() == 0x018 then
		print("Exchanging response with a modified HTTP response")
		local string = "Unencrypted HTTP is not very privacy conscious."
		tcp:payload(binary("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " .. string:len() .. "\r\nConnection: keep-alive\r\n\r\n" .. string .. "."))

		ip:payload(tcp)

		eth_frame:payload(ip)
		return eth_frame
	end

end



