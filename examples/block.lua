blocked_hosts = {
	"reddit.com"
}

function on_packet(eth_frame)
	local ip = eth_frame:ipv4()
	if ip == nil then
		return
	end

	if ip:protocol() == "Tcp" then
		local tcp = ip:tcp()
		if tcp:is_tls() then
			local tls = tcp:tls()
			local hello = tls:client_hello()
			-- Check whether the TLS packet is ClientHello
			if hello ~= nil then
				local sni = hello:sni()
				-- Check whether SNI is set
				if sni ~= nil then
					-- Check whether the SNI is in the blocked_hosts table
					-- If it is, drop the packet
					for _, blocked_host in ipairs(blocked_hosts) do
						if sni:find(blocked_host) then
							print("Blocking connection to " .. sni .. " (as per rule " .. blocked_host .. ")")
							eth_frame:drop()
						end
					end
				end
			end
		end
	end
	-- Return the packet, if no packet is returned, the untampered packet will be sent
	return eth_frame
end

