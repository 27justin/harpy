-- NOTE: it may take some time for this example to output data.
-- Only every 100 TLS ClientHello's is a status update outputted.
hosts = {}
acc = 0

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
					-- Check if the SNI is in the hosts table,
					-- if it is, add one to it's counter
					-- if it isn't, add it to the table with the value of 1
					if hosts[sni] == nil then
						hosts[sni] = 1
					else
						hosts[sni] = hosts[sni] + 1
					end
				end
				acc = acc + 1
			end
		end
	end

	if acc >= 100 then
		print("----------------")
		print("Status: ")
		print("")
		for host, count in pairs(hosts) do
			print(host .. ": " .. count)
		end
		acc = 0
		print("----------------")
	end

end


