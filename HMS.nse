local function check_multiple_vulnerabilities(ips_file, result_file, port)
	local file1 = io.open(ips_file, "r")
    local file2 = io.open(result_file, "w")
	if not file1 then
		print("[-]Failed to open file: "..file1)
	end
   if not file2 then
		print("[-]Failed to open file: "..file2)
	end
   local results = {}
	for ip in file1:lines() do
		local success = pcall(verify_vulnerability, ip, port)

		if success then
          table.insert(results, "VULNERABLE : "..ip)
       else
          table.insert(results, "NOT VULNERABLE : "..ip)
  end
 end
       
        for _, ip in ipairs(results) do
          print(ip .. "\n")
			file2:write(ip .. "\n")
          file2:flush()
	end
   file1:close()
	file2:close()
end