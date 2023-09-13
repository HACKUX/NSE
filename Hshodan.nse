local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local io = require "io"

description = "Extrait les adresses IP sur Shodan en utilisant un dork spécifié et les écrit dans un fichier via requête HTTP"
author = "Mr Hackux"
license = "MIT"
categories = {"discovery", "intrusive"}

--api.shodan.io

-- Fonction pour extraire les adresses IP sur Shodan
local function extractIPsFromShodan(host, port)
  local apiKey = "hsjkdkdkdkdkd"
  -- Dork Shodan à utiliser pour l'extraction des adresses IP
local shodanDork = "product:\"spip\""
  -- Chemin du fichier où écrire les adresses IP extraites
local outputFile = "/sdcard/Nmap/scripts/data/shodan.txt"
  
  if not apiKey or apiKey == "" then
    print("Clé API Shodan manquante. Utilisez l'argument 'http-search-shodan.apiKey' pour spécifier votre clé API.")
  end
  
  local p = "/shodan/host/search?key=" .. apiKey .. "&query=" .. shodanDork
print(p)
local opts = {header={}}
opts["header"]["User-Agent"] = 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0'
opts["header"]["Accept"] = '*/*' -- 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'

  
  local response = http.get(host, port, p, opts, nil, "")
  print(response.status)
  print(response. body)
  if response.status == 200 then
    local ipList = {}
    local data = stdnse.json2lua(response.body)
    if data and data["matches"] then
      for _, match in ipairs(data["matches"]) do
        if match["ip_str"] then
          table.insert(ipList, match["ip_str"])
        end
      end
    end
    
    if #ipList > 0 then
      local file = io.open(output, "w")
      for _, ip in ipairs(ipList) do
        file:write(ip .. "\n")
      end
      file:close()
      print("Adresses IP extraites et écrites dans le fichier '" .. output .. "'.")
    end
  end
  
  print("Aucune adresse IP trouvée ou erreur lors de l'extraction des adresses IP depuis Shodan.")
end

portrule = shortport.http
-- Fonction pour exécuter le script
action = function(host, port)
extractIPsFromShodan(host.ip, port)
 --local result = pcall(extractIPsFromShodan, host.ip, port.number)
    --if result then
    --  return result
 --   end
--  return stdnse.format_output(false, "Impossible d'extraire les adresses IP depuis Shodan.")
end