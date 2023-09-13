local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = "Cherche un texte dans le contenu d'une page web via requête HTTP"
author = "Mr Hackux"
license = "MIT"
categories = {"discovery", "intrusive"}

-- Fonction pour rechercher et afficher les formulaires avec l'attribut type="file"
local function searchContent(host, port)
  
end

portrule = shortport.http
-- Fonction pour exécuter le script
action = function(host, port)
 --local result = searchContent(host.ip, port.number)
 --local result = pcall(searchContent, host.ip, port.number)
    --if result then
      --return result
  --  end
--  return stdnse.format_output(false, "Impossible d'effectuer la recherche")


local path = "/pages/submit-a-fake"
  
  local opts = {header={}}
opts["header"]["User-Agent"] = 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0'
opts["header"]["Accept"] = '*/*' -- 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
  
  local response = http.get(host, port, path, opts, nil, "")
  print(response.status)
  --print(response.body)
  if response.status == 200 then

   local html = response.body
    -- Extract input types from HTML content
    local fileInputs = {}
     if string.find(html, "<form") then
        print("Exist !")
     else
         print("Don't exist !")
       end
    for input in html:gmatch("<input[^>]+type=\"file\"") do
      print(input)
      table.insert(fileInputs, input)
    end
    
    if #fileInputs > 0 then
      local output = ""
      for i, input in ipairs(fileInputs) do
        output = output .. "Input #" .. i .. ":\n" .. input .. "\n\n"
      end
      stdnse.format_output(true, output)
    end
  end
  stdnse.format_output(false, "Aucun input <input> avec l'attribut type=\"file\" trouvé.")


end