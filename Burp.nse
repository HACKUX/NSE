author = {"Mr_Hackux", " <hackuxe@gmail.com>","Balgo Security"}
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
-- @usage nmap -p443 --script Burp.nse <target>
--captcha.balgogan.repl.co -d

portrule = shortport.http

action = function(host, port)

local uri = stdnse.get_script_args(SCRIPT_NAME .. ".uri") or '/component---src-templates-contentful-layout-js-5b65ebfbed0dfae3330.js'




local opts = {header={}}


--[[En-têtes général]]

--opts['header']['Accept-Encoding'] = 'gzip, deflate'

--opts['header']['Authorization'] = 'MxToken hZUPhAV4ELPrRm7U7JAKf5BnxJk6q7dcsvFdw6ZR4wRYdv7egHjwHEYBwXY4RkSZrAWde3XqVAQkxZNPysvHcpquA9sK9bsKmcTN'

--opts['header']['Content-Type'] = 'application/x-www-form-urlencoded'

--opts['header']['X-Requested-With'] ='XMLHttpRequest User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ------WebKitFormBoundaryIzvIrbHjHpxzepPi'

--options['header']['Forwarded'] = '"for="[127.0.0.1]:8000";by="[127.0.0.1]:9000"'

--opts['header']['Forwarded'] = 'by=\"[127.0.0.1]:8888\";for=\"[127.0.0.1]:8888\";proto=http;host='
--options['header']['Forwarded-Vdom'] = 'root'
opts['header']['Accept'] ='application/json, text/javascript, */*; q=0.01'

--[[Date: <day-name>, <jour> <mois> <année> <heure>:<minute>:<seconde> GMT]]
--opts["header"]["Date"] = 'Wed, 21 Oct 2015 07:28:00 GMT'

-- [[Cache-Control :RequêteRéponsemax-agemax-agemax-stale-min-fresh--s-maxageno-cacheno-cacheno-storeno-storeno-transformno-transformonly-if-cached--must-revalidate-proxy-revalidate-must-understand-private-public-immutable-stale-while-revalidatestale-if-error]]
--opts["header"]["Cache-Control"] = 'max-age=0'

--[[Connection: keep-alive Connection: close]]
--opts["header"]["Connection"] = 'keep-alive'


--[[En-têtes requête]]
--[[Accept: <MIME_type>/<MIME_subtype> Accept: <MIME_type>/* Accept: */*]]
--opts["header"]["Accept"] = '*/*' -- 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'

--opts["header"]["Accept-Encodig"] = 'en-US,en;q=0.5'

--[[Accept-Language: <langue> Accept-Language: <locale> Accept-Language: *]]
--opts["header"]["Accept-Language"] = 'en-US,en;q=0.5'

--[[If-Modified-Since: <label-jour>, <jour> <mois> <année><heure>:<minute>:<seconde> GMT / "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", ou "Sun" ]]
--opts["header"]["If-Modified-Since"] = 'Fri, 21 Oct 2022 07:28:00 GMT'

--[[Cookie: <cookie-list> Cookie: name=value Cookie: name=value; name2=value2; name3=value3]]
--opts["header"]["Cookie"] = req.header["set-cookie"]

--[[User-Agent: <product> / <product-version> <comment>]]
opts["header"]["User-Agent"] = 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0'

--[[Referer: <url>]]
--opts["header"]["Referer"] = 'http://localhost:8080/tasks/create'

--opts["header"]["DNT"] = 1

--opts["header"]["Content-Disposition"] ='form-data; name="size_limit" 2e+9 ------WebKitFormBoundaryIzvIrbHjHpxzepPi'

--opts["header"]["Content-Disposition"] = 'form-data; name="action" dnd_codedropz_upload ------WebKitFormBoundaryIzvIrbHjHpxzepPi'

--opts["header"]["Content-Disposition"] ='form-data; name="upload_dir" ../../../ ------WebKitFormBoundaryIzvIrbHjHpxzepPi'

--opts["header"]["Content-Disposition"] = 'form-data; name="upload_dir" ../../../ ------WebKitFormBoundaryIzvIrbHjHpxzepPi' 

--opts["header"]["Content-Disposition"] = 'form-data; name="post_id" 1868 ------WebKitFormBoundaryIzvIrbHjHpxzepPi'

--opts["header"]["Content-Disposition"] = 'form-data; name="security" 0a4dca2b89 ------WebKitFormBoundaryIzvIrbHjHpxzepPi'

--opts["header"]["Content-Disposition"] = 'form-data; name="form_id" 9210 ------WebKitFormBoundaryIzvIrbHjHpxzepPi'

--opts["header"]["Content-Disposition"] = 'form-data; name="upload_name" foto ------WebKitFormBoundaryIzvIrbHjHpxzepPi'

--opts["header"]["Content-Disposition"] ='form-data; name="upload-file"; filename="/sdcard/file.jpg"'

--opts["header"]["Content-Type"] = 'image/jpg// image contents ------WebKitFormBoundaryIzvIrbHjHpxzepPi--'


--[[Content-Length: <longueur>]]
--opts["header"]["Content-Length"] = '2255'

--opts["header"]["Origin"] = host.ip

--opts["header"]["Authorization"] = 'Token 06d88f739a10c7533991d8010761df721b790b7'
--opts["header"]["X-CSRFTOKEN"] = '65s9UwX36e9v8FyiJi0KEzgMigJ5pusEK7dU4KSqgCajSBAYQxKDYCOEVBUhnIGV'

--opts["header"]["Sec-Ch-Ua"] = '"chromuim";v="109", "Not_At_Brand";v="99"'
--opts["header"]["Sec-Ch-Ua-Mobile"] = '?0'
--opts["header"]["Sec-Ch-Ua-Platform"] = 'Linux'
--opts["header"]["Sec-Fetch-Dest"] = 'empty'
--opts["header"]["Sec-Fetch-Mode"] = 'cors'
--opts["header"]["Sec-Fetch-Site"] = 'same-origin'
print(" ############BURP##########")
print("\n")

local req = http.get(host, port, uri, opts, nil, "")
print(" \n\n")
print(req.body)
print("\n\n")
print("#########################")
end