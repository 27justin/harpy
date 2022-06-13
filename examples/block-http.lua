function on_packet(eth_frame)
	local ip = eth_frame:ipv4()
	if ip == nil then
		return
	end

	local tcp = ip:tcp()
	if tcp == nil then
		return
	end

	if tcp:src_port() == 80 or tcp:dst_port() == 80 then
		print("Dropping HTTP request")
		eth_frame:drop()
		return eth_frame
	end
end

