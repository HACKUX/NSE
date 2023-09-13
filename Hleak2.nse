local string = require "string"
local httpspider = require "httpspider"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"


description = [[
Spiders a website and attempts to match all pages and urls against a given
string. Matches are counted and grouped per url under which they were
discovered.

Features built in patterns like email, ip, ssn, discover, amex and more.
The script searches for email and ip by default.

And searches leak data

]]

---
-- @usage
-- nmap -p 80 www.example.com --script Hleak.nse --script-args='match="[A-Za-z0-9%.%%%+%-]+@[A-Za-z0-9%.%%%+%-]+%.%w%w%w?%w?",breakonmatch'
-- nmap -p 80 www.example.com --script Hleak.nse --script-args 'http-grep.builtins ={"mastercard", "discover"}, http-grep.url="example.html"'


author = {"Mr Hackux", "Balgo city"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.http


action = function(host, port)

local opts = {header={}}
opts["header"]["User-Agent"] = 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0'
opts["header"]["Accept"] = '*/*' -- 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'


local url = stdnse.get_script_args(SCRIPT_NAME .. ".url") or '/how-it-works'

print("############ HLEAK ##########")

local req = http.get(host, port, url, opts, nil, "")
local b = req.body

print("\n\n")
print("BODY")
for regt in b:gmatch('<title>.-</title>') do
print(regt)
end


--exgrep (pemprivate|PEMPRIVATE)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (preprod|PREPROD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (private_key|PRIVATE_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (prod|PROD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (pwd|PWD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (pwds|PWDS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (rds.amazonaws.compassword|RDS.AMAZONAWS.COMPASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (redis_password|REDIS_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (root_password|ROOT_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (secret|SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (secret.password|SECRET.PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (secret_access_key|SECRET_ACCESS_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (secret_key|SECRET_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (secret_token|SECRET_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (secrets|SECRETS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (secure|SECURE)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} 

local reg193 = b:match('pemprivate.-"')
local reg194 = b:match('PEMPRIVATE.-"')
local reg195 = b:match('preprod.-"')
local reg196 = b:match('PREPROD.-"')
local reg197 = b:match('private_key.-"')
local reg198 = b:match('PRIVATE_KEY.-"')
local reg199 = b:match('prod.-"')
local reg200 = b:match('pwd.-"')
local reg201 = b:match('PWD.-"')
local reg202 = b:match('pwds.-"')
local reg203 = b:match('PWDS.-"')
local reg204 = b:match('rds.amazonaws.compassword.-"')
local reg205 = b:match('RDS.AMAZONAWS.COMPASSWORD.-"')
local reg206 = b:match('redis_password.-"')
local reg207 = b:match('REDIS_PASSWORD.-"')
local reg208 = b:match('root_password.-"')
local reg209 = b:match('ROOT_PASSWORD.-"')
local reg210 = b:match('secret.-"')
local reg211 = b:match('SECRET.-"')
local reg212 = b:match('secret.password.-"')
local reg213 = b:match('SECRET.PASSWORD.-"')
local reg214 = b:match('secret_access_key.-"')
local reg215 = b:match('SECRET_ACCESS_KEY.-"')
local reg216 = b:match('secret_key.-"')
local reg217 = b:match('SECRET_KEY.-"')
local reg218 = b:match('secret_token.-"')
local reg219 = b:match('SECRET_TOKEN.-"')
local reg220 = b:match('secret.-"')
local reg221 = b:match('SECRETS.-"')
local reg222 = b:match('secure.-"')
local reg223 = b:match('SECURE.-"')

--exgrep (security_credentials|SECURITY_CREDENTIALS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (send.keys|SEND.KEYS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (send_keys|SEND_KEYS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (sf_username|SF_USERNAME)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (slack_api|SLACK_API)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (slack_token|SLACK_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (sql_password|SQL_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (ssh|SSH)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (ssh2_auth_password|SSH2_AUTH_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (sshpass|SSHPASS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (staging|STAGING)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (stg|STG)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (storePassword|STOREPASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (stripe|STRIPE)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (swagger|SWAGGER)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (testuser|TESTUSER)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100}
local reg224 = b:match('security_credentials.-"')
local reg225 = b:match('SECURITY_CREDENTIALS.-"')
local reg226 = b:match('send.keys.-"')
local reg227 = b:match('SEND.KEYS.-"')
local reg228 = b:match('sf_username.-"')
local reg229 = b:match('SF_USERNAME.-"')
local reg230 = b:match('slack_api.-"')
local reg231 = b:match('SLACK_API.-"')
local reg232 = b:match('SLACK_TOKEN.-"')
local reg233 = b:match('slack_token.-"')
local reg234 = b:match('sql_password.-"')
local reg235 = b:match('SQL_PASSWORD.-"')
local reg236 = b:match('ssh.-"')
local reg237 = b:match('SSH.-"')
local reg238 = b:match('ssh2_auth_password.-"')
local reg239 = b:match('SSH2_AUTH_PASSWORD.-"')
local reg240 = b:match('sshpass.-"')
local reg241 = b:match('SSHPASS.-"')
local reg242 = b:match('staging.-"')
local reg243 = b:match('STAGING.-"')
local reg244 = b:match('stg.-"')
local reg245 = b:match('STG.-"')
local reg246 = b:match('storePassword.-"')
local reg247 = b:match('STOREPASSWORD.-"')
local reg248 = b:match('stripe.-"')
local reg249 = b:match('STRIPE.-"')
local reg250 = b:match('swagger.-"')
local reg251 = b:match('SWAGGER.-"')
local reg252 = b:match('testuser.-"')
local reg253 = b:match('TESTUSER.-"')


if reg193 ~= nil then
print("\n\n")
print("Leak 193")
print(reg193)
print("\n\n")
end
if reg194 ~= nil then
print("\n\n")
print("Leak 194")
print(reg194)
print("\n\n")
end
if reg195 ~= nil then
print("\n\n")
print("Leak 195")
print(reg195)
print("\n\n")
end
if reg196 ~= nil then
print("\n\n")
print("Leak 196")
print(reg196)
print("\n\n")
end
if reg197 ~= nil then
print("\n\n")
print("Leak 197")
print(reg197)
print("\n\n")
end
if reg198 ~= nil then
print("\n\n")
print("Leak 198")
print(reg198)
print("\n\n")
end
if reg199 ~= nil then
print("\n\n")
print("Leak 199")
print(reg199)
print("\n\n")
end
if reg200 ~= nil then
print("\n\n")
print("Leak 200")
print(reg200)
print("\n\n")
end
if reg201 ~= nil then
print("\n\n")
print("Leak 201")
print(reg201)
print("\n\n")
end
if reg202 ~= nil then
print("\n\n")
print("Leak 202")
print(reg202)
print("\n\n")
end
if reg203 ~= nil then
print("\n\n")
print("Leak 203")
print(reg203)
print("\n\n")
end
if reg204 ~= nil then
print("\n\n")
print("Leak 204")
print(reg204)
print("\n\n")
end
if reg205 ~= nil then
print("\n\n")
print("Leak 205")
print(reg205)
print("\n\n")
end
if reg206 ~= nil then
print("\n\n")
print("Leak 206")
print(reg206)
print("\n\n")
end
if reg207 ~= nil then
print("\n\n")
print("Leak 207")
print(reg207)
print("\n\n")
end
if reg208 ~= nil then
print("\n\n")
print("Leak 208")
print(reg208)
print("\n\n")
end
if reg209 ~= nil then
print("\n\n")
print("Leak 209")
print(reg209)
print("\n\n")
end
if reg210 ~= nil then
print("\n\n")
print("Leak 210")
print(reg210)
print("\n\n")
end
if reg211 ~= nil then
print("\n\n")
print("Leak 211")
print(reg211)
print("\n\n")
end
if reg212 ~= nil then
print("\n\n")
print("Leak 212")
print(reg212)
print("\n\n")
end
if reg213 ~= nil then
print("\n\n")
print("Leak 213")
print(reg213)
print("\n\n")
end
if reg214 ~= nil then
print("\n\n")
print("Leak 214")
print(reg214)
print("\n\n")
end
if reg215 ~= nil then
print("\n\n")
print("Leak 215")
print(reg215)
print("\n\n")
end
if reg216 ~= nil then
print("\n\n")
print("Leak 216")
print(reg216)
print("\n\n")
end
if reg217 ~= nil then
print("\n\n")
print("Leak 217")
print(reg217)
print("\n\n")
end
if reg218 ~= nil then
print("\n\n")
print("Leak 218")
print(reg218)
print("\n\n")
end
if reg219 ~= nil then
print("\n\n")
print("Leak 219")
print(reg219)
print("\n\n")
end
if reg220 ~= nil then
print("\n\n")
print("Leak 220")
print(reg220)
print("\n\n")
end
if reg221 ~= nil then
print("\n\n")
print("Leak 221")
print(reg221)
print("\n\n")
end
if reg222 ~= nil then
print("\n\n")
print("Leak 222")
print(reg222)
print("\n\n")
end
if reg223 ~= nil then
print("\n\n")
print("Leak 223")
print(reg223)
print("\n\n")
end
if reg224 ~= nil then
print("\n\n")
print("Leak 224")
print(reg224)
print("\n\n")
end
if reg225 ~= nil then
print("\n\n")
print("Leak 225")
print(reg225)
print("\n\n")
end
if reg226 ~= nil then
print("\n\n")
print("Leak 226")
print(reg226)
print("\n\n")
end
if reg227 ~= nil then
print("\n\n")
print("Leak 227")
print(reg227)
print("\n\n")
end
if reg228 ~= nil then
print("\n\n")
print("Leak 228")
print(reg228)
print("\n\n")
end
if reg229 ~= nil then
print("\n\n")
print("Leak 229")
print(reg229)
print("\n\n")
end
if reg230 ~= nil then
print("\n\n")
print("Leak 230")
print(reg230)
print("\n\n")
end
if reg231 ~= nil then
print("\n\n")
print("Leak 231")
print(reg231)
print("\n\n")
end
if reg232 ~= nil then
print("\n\n")
print("Leak 232")
print(reg232)
print("\n\n")
end
if reg233 ~= nil then
print("\n\n")
print("Leak 233")
print(reg233)
print("\n\n")
end
if reg234 ~= nil then
print("\n\n")
print("Leak 234")
print(reg234)
print("\n\n")
end
if reg235 ~= nil then
print("\n\n")
print("Leak 235")
print(reg235)
print("\n\n")
end
if reg236 ~= nil then
print("\n\n")
print("Leak 236")
print(reg236)
print("\n\n")
end
if reg237 ~= nil then
print("\n\n")
print("Leak 237")
print(reg237)
print("\n\n")
end
if reg238 ~= nil then
print("\n\n")
print("Leak 238")
print(reg238)
print("\n\n")
end
if reg239 ~= nil then
print("\n\n")
print("Leak 239")
print(reg239)
print("\n\n")
end
if reg240 ~= nil then
print("\n\n")
print("Leak 240")
print(reg240)
print("\n\n")
end
if reg241 ~= nil then
print("\n\n")
print("Leak 241")
print(reg241)
print("\n\n")
end
if reg242 ~= nil then
print("\n\n")
print("Leak 242")
print(reg242)
print("\n\n")
end
if reg243 ~= nil then
print("\n\n")
print("Leak 243")
print(reg243)
print("\n\n")
end
if reg244 ~= nil then
print("\n\n")
print("Leak 244")
print(reg244)
print("\n\n")
end
if reg245 ~= nil then
print("\n\n")
print("Leak 245")
print(reg245)
print("\n\n")
end
if reg246 ~= nil then
print("\n\n")
print("Leak 246")
print(reg246)
print("\n\n")
end
if reg247 ~= nil then
print("\n\n")
print("Leak 247")
print(reg247)
print("\n\n")
end
if reg248 ~= nil then
print("\n\n")
print("Leak 248")
print(reg248)
print("\n\n")
end
if reg249 ~= nil then
print("\n\n")
print("Leak 249")
print(reg249)
print("\n\n")
end
if reg250 ~= nil then
print("\n\n")
print("Leak 250")
print(reg250)
print("\n\n")
end
if reg251 ~= nil then
print("\n\n")
print("Leak 251")
print(reg251)
print("\n\n")
end
if reg252 ~= nil then
print("\n\n")
print("Leak 252")
print(reg252)
print("\n\n")
end
if reg253 ~= nil then
print("\n\n")
print("Leak 253")
print(reg253)
print("\n\n")
end


print("#######################")

end