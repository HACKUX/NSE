-- Script: extract_ips.lua

-- Chargement du module "file" pour la lecture et l'écriture de fichiers
local io = require "io"
local string = require "string"
local shortport = require "shortport"

portrule = shortport.http

-- Déclaration du nom du script NSE
local name = "extract_ips"

-- La fonction principal du script
local function run_script(host, port)

  
  -- Chemin d'accès au fichier contenant les adresses IP à extraire
  local file_path = "/sdcard/Nmap/data/vmwareips.txt"

  -- Ouvrir le fichier en lecture seule
  local file = io.open(file_path, "r")

  -- Vérifier si le fichier a été ouvert avec succès
  if not file then
    return nil, string.format("Impossible d'ouvrir le fichier %s", file_path)
  end
  
  	-- Expression régulière pour extraire les adresses IP 
	local regex_pattern = "%d+%.%d+%.%d+%.%d+" 

	-- Tableau pour stocker les adresses IP extraites 
	local ips = {}

	-- Lire chaque ligne du fichier 
	for line in file:lines() do
		
		-- Rechercher toutes les occurrences d'adresses IP dans la ligne actuelle 
		for ip in line:gmatch(regex_pattern) do
			
			-- Ajouter l'adresse IP trouvée au tableau 
			table.insert(ips, ip)
			
		end
		
	end
  
  	-- Fermer le fichier après utilisation
	file:close()

	-- Chemin d'accès au fichier de destination où les adresses IP seront écrites ligne par ligne 
	local destination_file_path = "/sdcard/Nmap/data/vmwareips2.txt"

    -- Ouvrir le fichier en mode append (ajout à la fin) ou créer s'il n'existe pas 
	local destination_file = io.open(destination_file_path, "a")

	-- Écrire chaque adresse IP dans le fichier de destination 
	for _, ip in ipairs(ips) do
		destination_file:write(ip .. "\n")
	end

  	-- Fermer le fichier de destination après utilisation
	destination_file:close()

  	-- Retourner un message de succès avec le chemin d'accès au fichier de destination
	return string.format("Adresses IP extraites et enregistrées avec succès dans le fichier %s", destination_file_path)
end

-- Déclaration des arguments du script
action = function(host, port)
	return run_script(host, port)
end