host = "192.168.0.53"

function on_packet(eth_frame)
	local ip = eth_frame:ipv4()
	if ip == nil then
		return
	end

	if ip:src() == host then
		eth_frame:drop()
		return eth_frame
	end
end

