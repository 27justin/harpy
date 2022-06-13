function dump_sni(hello, ip)
	print("[" .. os.date("%H:%M:%S") .. "]: " .. ip:src() .. " is visiting " .. hello:sni())
end
function dump_quic_sni(hello, ip)
	print("QUIC:: [" .. os.date("%H:%M:%S") .. "]: " .. ip:src() .. " is visiting " .. hello:sni())
end


function on_packet(eth_frame)
	local ip = eth_frame:ipv4()
	if ip then
		if ip:protocol() == "Tcp" then
			local tcp = ip:tcp()
			if tcp:is_tls() then
				local tls = tcp:tls()
				local client_hello = tls:client_hello()
				if client_hello ~= nil then
					dump_sni(client_hello, ip)
				end
			end
		elseif ip:protocol() == "Udp" then
			local udp = ip:udp()
			if udp:is_quic() then
				local quic = udp:quic()
				--[[local client_hello = quic:client_hello()
				if client_hello ~= nil then
					dump_quic_sni(client_hello, ip)
				end]]

			end
		end
	end
end
