local string = require "string"
local httpspider = require "httpspider"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local io = require "io"


description = [[
Subdomains finder.

]]

---
-- @usage
-- nmap -p 443 --script hsubfinder.nse <target>

author = {"Mr Hackux", "Balgo city"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.http
action = function(host, port)

local opts = {header={}}
opts["header"]["User-Agent"] = 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0'
opts["header"]["Accept"] = '*/*' -- 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'


local url = stdnse.get_script_args(SCRIPT_NAME .. ".url") or '/'

print("############ HSUBFINDER ##########")

local file = "/sdcard/Nmap/data/HACKUX/sub.txt"
local file2 = "/sdcard/Nmap/data/HACKUX/sub2.txt"
local f = assert(io.open(file, 'r'))

local subs = {}
for sub in f:lines() do
--print(sub)
local hostname = 'google.com'
local subdomain = sub.."."..hostname
print(subdomain)
local req = http.get(subdomain, port, url, opts, nil, "")
if req.status == 200 then
table.insert(subs, sub)
end
end
f:close()


local f2 = assert(io.open(file2, 'w'))
print("Finding subs:")
for i, sub in ipairs(subs) do
print(i .. ": " .. sub)
  file:write(sub)
  end
  file:close()

end