-- Nom du script: http-file-enum.nse
-- Auteur: [Votre nom ici]
-- Description: Énumère les fichiers sur un hôte en utilisant une wordlist et des requêtes HTTP
-- Catégorie: découverte

local string = require "string"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"
local table = require "table"
local io = require "io"

portrule = shortport.http

-- Fonction principale
action = function(host, port)

local opts = {header={}}
opts["header"]["User-Agent"] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36'

  -- Charge la wordlist
  local filenames = {}
  local file = io.open("/sdcard/Nmap/data/wordlist.txt", "r")
  local file2 = io.open("/sdcard/Nmap/data/ffound.txt", "w")
  for line in file:lines() do
    --print(line)
    table.insert(filenames, line)
  end
  file:close()

  -- Effectue des requêtes HTTP pour chaque fichier dans la wordlist
  for _, filename in ipairs(filenames) do
    local response = http.get(host, port, filename, opts, nil, "")

    -- Vérifie si le fichier existe
    if response.status == 200 then
      -- Affiche le chemin d'accès du fichier si celui-ci existe
      print("FOUND !: " .. host.ip..filename)
      file2:write("FOUND ! : " .. host.ip..filename)
      file2:flush() -- Force l'écriture immédiate dans le fichier

    else
       print("NOT FOUND ! : " .. host.ip..filename)
    end
  end
file2:close()
end