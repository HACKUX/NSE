local string = require "string"
local httpspider = require "httpspider"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"
local table = require "table"
local io = require "io"

local file = io.open("/sdcard/Nmap/data/xss.txt", "a") -- Ouvre le fichier en mode ajout
local file2 = io.open("/sdcard/Nmap/data/xss.html", "a")

local function extract_urls(response)
  local urls = {}

  -- Extraire les URL des attributs href
  for url in response.body:gmatch('href="(.-)"') do
    if string.find(url, "=") then
      table.insert(urls, url)
    end
  end

  -- Extraire les URL des attributs src
  for url in response.body:gmatch('src="(.-)"') do
    if string.find(url, "=") then
      table.insert(urls, url)
    end
  end

  return urls
end

local function modify_urls(urls)
  local modified_urls = {}

  for _, url in ipairs(urls) do
    local modified_url = string.gsub(url, "=(.-)", "=<h1>Hackux</h1>")

 if(string.match(modified_url,'http')) then
 local _, _, uri = string.find(modified_url, "^.*://[^/]+(/.+)$")
-- print(uri)
    table.insert(modified_urls, uri)
else
 local uri = modified_url
-- print(uri)
    table.insert(modified_urls, uri)
end

  end

  return modified_urls
end

local function check_text(response)
  if string.find(response.body, "<h1>Hackux</h1>") then
    return true
  else
    return false
  end
end

local function log_action(url, text_found, rep, host)
if text_found then
  local log = string.format("URL: %s -  XSS DETECTE ! : %s\n", host.ip..url, tostring(text_found))
  file:write(log)
  file:flush() -- Force l'écriture immédiate dans le fichier
  file2:write(rep)
  file2:flush()
print(string.format("URL: %s - XSS DETECTED !: %s\n", host.ip..url, tostring(text_found)))
else
     local log = string.format("URL: %s -  Not Found ! : %s\n", host.ip..url, tostring(text_found))
  --file:write(log)
  --file:flush() -- Force l'écriture immédiate dans le fichier
print(string.format("URL: %s - Not Found ! : %s\n", host.ip..url, tostring(text_found)))
end

end

portrule = shortport.http
action = function(host, port)

local opts = {header={}}
opts["header"]["User-Agent"] = 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0'
opts["header"]["Accept"] = '*/*' -- 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'

  --local target = string.format("http://%s:%d", host, port)
  local response = http.get(host, port, "/", opts, nil, "")

local html = response.body
--print(html)

    -- Extract input names from HTML content
    local inputs = {}
    for input in html:gmatch("<input[^>]+name=\"([^\"]+)\"") do
      --print(" ?"..input)
      table.insert(inputs, input)
    end

    -- Perform POST requests with each input name as URI
    for _, input in ipairs(inputs) do
      local postUri = "/"
      local postData = "?" .. input.."=<h1>Hackux</h1>"
      local postResponse = http.post(host, port, postUri..postData, opts, nil, "")

      if postResponse and postResponse.status == 200 and postResponse.body then
        local postHtml = postResponse.body

        -- Check if the response contains "<h1>Hackux</h1>"
        
        

        local text_found2 = check_text(postResponse)
    log_action(postUri..postData, text_found2, postResponse, host)
      end
    end


  local urls = extract_urls(response)
  local modified_urls = modify_urls(urls)
  local getUri = "/"

  for _, url in ipairs(modified_urls) do
    local modified_response = http.get(host, port, url, opts, nil, "")
    print(modified_response.status)
    local mr = modified_response.body
    --print(mr)
    local text_found = check_text(modified_response)
    log_action(getUri..url, text_found, mr, host)

  end

end