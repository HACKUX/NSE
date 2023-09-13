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


local url = stdnse.get_script_args(SCRIPT_NAME .. ".url") or '/'

print("############ HLEAK ##########")

local req = http.get(host, port, url, opts, nil, "")
local b = req.body

print("\n\n")
print("BODY")
--for regt in b:gmatch('<title>.-</title>') do
--print(regt)
--print(b)
--end
print("\n\n")
print(" \n\n")
print("HREF")
for regh in b:gmatch('href=".-"') do
print(regh)
if(string.match(regh,'href="http://')) then
local regh1 = string.gsub(regh,'http://.-/','/')
print(regh1)
local regh2 = string.gsub(regh1,'href=','')
local regh3 = string.gsub(regh1,'"','')
local reqh = http.get(host, port, regh3, opts, nil, "")
local regh4 = reqh.body:match('key.-"')
local regh5 = reqh.body:match('Key.-"')
local regh6 = reqh.body:match('KEY.-"')
if regh4 ~= nil then
print("Leak ")
print(regh4)
end
if regh5 ~= nil then
print("Leak ")
print(regh5)
end
if regh6 ~= nil then
print("Leak ")
print(regh6)
end

else if(string.match(regh,'href="https://')) then
local regh1 = string.gsub(regh,'https://.-/','/')
print(regh1)
local regh2 = string.gsub(regh1,'href=','')
local regh3 = string.gsub(regh1,'"','')
local reqh = http.get(host, port, regh3, opts, nil, "")
local regh4 = reqh.body:match('key.-"')
local regh5 = reqh.body:match('Key.-"')
local regh6 = reqh.body:match('KEY.-"')
if regh4 ~= nil then
print("Leak ")
print(regh4)
end
if regh5 ~= nil then
print("Leak ")
print(regh5)
end
if regh6 ~= nil then
print("Leak ")
print(regh6)
end


else
local regh1 = string.gsub(regh,'href=','')
local regh2 = string.gsub(regh1,'"','')
local reqh = http.get(host, port, regh2, opts, nil, "")
local regh4 = reqh.body:match('key.-"')
local regh5 = reqh.body:match('Key.-"')
local regh6 = reqh.body:match('KEY.-"')
if regh4 ~= nil then
print("Leak ")
print(regh4)
end
if regh5 ~= nil then
print("Leak ")
print(regh5)
end
if regh6 ~= nil then
print("Leak ")
print(regh6)
end
end
end
end

print(" \n\n")
print("SRC")
for regs in b:gmatch('src=".-"') do
print(regs)
if(string.match(regs,'href="http://')) then
local regs1 = string.gsub(regs,'http://.-/','/')
print(regs1)
local regs2 = string.gsub(regs1,'href=','')
local regs3 = string.gsub(regs1,'"','')
local reqs = http.get(host, port, regs3, opts, nil, "")
local regs4 = reqs.body:match('key.-"')
local regs5 = reqs.body:match('Key.-"')
local regs6 = reqs.body:match('KEY.-"')
if regs4 ~= nil then
print("Leak ")
print(regs4)
end
if regs5 ~= nil then
print("Leak ")
print(regs5)
end
if regs6 ~= nil then
print("Leak ")
print(regs6)
end

else if(string.match(regs,'href="https://')) then
local regs1 = string.gsub(regs,'https://.-/','/')
print(regs1)
local regs2 = string.gsub(regs1,'href=','')
local regs3 = string.gsub(regs1,'"','')
local reqs = http.get(host, port, regs3, opts, nil, "")
local regs4 = reqs.body:match('key.-"')
local regs5 = reqs.body:match('Key.-"')
local regs6 = reqs.body:match('KEY.-"')
if regs4 ~= nil then
print("Leak ")
print(regs4)
end
if regs5 ~= nil then
print("Leak ")
print(regs5)
end
if regs6 ~= nil then
print("Leak ")
print(regs6)
end


else
local regs1 = string.gsub(regs,'href=','')
local regs2 = string.gsub(regs1,'"','')
local reqs = http.get(host, port, regs2, opts, nil, "")
local regs4 = reqs.body:match('key.-"')
local regs5 = reqs.body:match('Key.-"')
local regs6 = reqs.body:match('KEY.-"')
if regs4 ~= nil then
print("Leak ")
print(regs4)
end
if regs5 ~= nil then
print("Leak ")
print(regs5)
end
if regs6 ~= nil then
print("Leak ")
print(regs6)
end
end
end
end

print(" \n\n")
print("INPUT")
for regi in b:gmatch('<input.-/>') do
print(regi)
for reginame in regi:gmatch('name=".-"') do
local reginame1 = string.gsub(reginame,'name=','')
local reginame2 = string.gsub(reginame,'"','')
local payload = reginame2..'=<button onclick="alert(1)">Hackux</button>'
print(payload)
local req = http.post(host, port, '/', opts, nil, payload)
if(string.find(req.body,'<button onclick="alert(1)">Hackux</button>')) then
print("XSS DETECTED !!!")
end
end
end
print("\n\n")



--exreg1 amzn.mws]{8}-[0-9a-f]{4}-10-9a-f1{4}-[0-9a,]{4}-[0-9a-f]{12}
local reg1 = b:match('amzn.mw.-"')

--exreg2 (A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}
--exresult 
local reg2 = b:match('A3T.-"')
local reg3 = b:match('AKIA.-"')
local reg4 = b:match('AGPA.-"')
local reg5 = b:match('AROA.-"')
local reg6 = b:match('AIPA.-"')
local reg7 = b:match('ANPA.-"')
local reg8 = b:match('ANVA.-"')
local reg9 = b:match('ASIA.-"')

--exgrep https:\/\/hooks.slack.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}
local reg10 = b:match('https://hooks.slack.com/services.-"')

--exgrep virustotal[_-]?apikey(=| =|:| :)
local reg11 = b:match('https://www.virustotal.com/vtapi/v2/file/report?apikey=.-"')

--exgrep TOKEN[\\-|_|A-Z0-9]*(\'|\")?(:|=)(\'|\")?[\\-|_|A-Z0-9]{10}
local reg12 = b:match('TOKEN.-"')

--exgrep xoxb-[0-9A-Za-z\\-]{50}
local reg13 = b:match('xoxb.-"')

--exgrep xoxp-[0-9A-Za-z\\-]{71}
local reg14 = b:match('xoxp.-')

--exgrep token=[0-9A-Za-z\\-]{5,100}
local reg15 = b:match('token=.-"')

--exgrep (SECRET|secret)(:|=| : | = )("|')[0-9A-Za-z\\-]{10}
--exgrep secret[_-]?0(=| =|:| :)
local reg16 = b:match('SECRET.-"')
local reg17 = b:match('secret.-"')

--exgrep (key|KEY)(:|=)[0-9A-Za-z\\-]{10}
local reg18 = b:match('KEY.-"')
local reg19 = b:match('Key = ".-"')

--Branch.io API key
local reg20 = b:match('key_live_.-"')

 --exgrep(password|PASSWORD)(:|=| : | = )("|')[0-9A-Za-z\\-]{10}
local reg21 = b:match('PASSWORD.-"')
local reg22 = b:match('password.-"')

--exgrep [0-9(+-[0-9A-Za-z_]{32}.apps.qooqleusercontent.com
local reg23 = b:match('apps.googleusercontent.com.-"')

--exgrep R_[0-9a-f]{32}
local reg24 = b:match('R_.-"')

--exgrep sk_live_[0-9a-z]{32}
local reg25 = b:match('sk_live_.-"')

--exgrep access_token,production$[0-9a-z]{161[0-9a,]{32}
local reg26 = b:match('access_token.-"')

--exgrep key-[0-9a-zA-Z]{32}
local reg27 = b:match('key-.-"')

--exgrep xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}
local reg28 = b:match('xoxbaprs-.-"')

--exgrep AKIA[0-9A-Z]{16}
local reg29 = b:match('AKIA.-"')

--exgrep basic [a-zA-Z0-9]
local reg30 = b:match('basic.-"')

--exgrep bearer [a-zA-Z0-9]
local reg31 = b:match('bearer.-"')

--exgrep EAACEdEose0cBA[0-9A-Za-z]+
local reg32 = b:match('EAACEdEose0cBA.-"')



--exgrep AIza[0-9A-Za-z\\-_]{35}
local reg38 = b:match('AIza.-"')

--exgrep ya29\\.[0-9A-Za-z\\-_]+
local reg39 = b:match('ya29.-"')

--exgrep xox[baprs]-([0-9a-zA-Z]{10,48})
local reg40 = b:match('xoxbaprs-+.-"')

--exgrep sqOatp-[0-9A-Za-z\\-_]{22}
local reg41 = b:match('sqOatp-.-"')

--exgrep sq0csp-[ 0-9A-Za-z\\-_]{43}
local reg42 = b:match('sq0csp-.-"')

--exgrep SK[0-9a-fA-F]{32}
local reg43 = b:match('SK.-"')

--exgrep (?i)twitter(.{0,20})?['\"][0-9a-z]{18,25}
local reg44 = b:match('twitter.-"')

--exgrep [t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]
local reg45 = b:match('TWITTER.-"')

--exgrep AAAA[A-Za-z0-9_-]{5,100}:[A-Za-z0-9_-]{140}
local reg46 = b:match('AAAA.-"')

--exgrep 6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$ 
local reg47 = b:match('6L.-"')

--exgrep s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*
local reg48 = b:match('s3.amazonaws.com.-"')

--exgrep api[key|_key|\s+]+[a-zA-Z0-9_\-]{7,100}
local reg49 = b:match('apiKey.-"')
local reg50 = b:match('api_Key.-"')

--exgrep SK[0-9a-fA-F]{32} AC[a-zA-Z0-9_\-]{32} AP[a-zA-Z0-9_\-]{32} 
local reg51 = b:match('SK.-"')
local reg52 = b:match('AC.-"')
local reg53 = b:match('AP.-"')

--exgrep rk_live_[0-9a-zA-Z]{24} [a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*  \"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\" ([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+) 
local reg54 = b:match('rk_live.-"')
local reg55 = b:match('@github.com.-"')
local reg56 = b:match('api_token.-"')
local reg57 = b:match('PRIVATE KEY.-"')

--exgrep (SF_USERNAMEsalesforce|SF_USERNAMESALESFORCE)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (access_key|ACCESS_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (access_token|ACCESS_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (amazonaws|AMAZONAWS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (apiSecret|APISECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (api_key|API_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (api_secret|API_SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (apidocs|APIDOCS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (apikey|APIKEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (app_key|APP_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} 
local reg58 = b:match('SF_USERNAMEsalesforce.-"')
local reg59 = b:match('twitter.-"')
local reg60 = b:match('SF_USERNAMESALESFORCE.-"')
local reg61 = b:match('access_key.-"')
local reg62 = b:match('ACCESS_KEY.-"')
local reg63 = b:match('ACCESS_TOKEN.-"')
local reg64 = b:match('amazonaws.-"')
local reg65 = b:match('AMAZONAWS.-"')
local reg66 = b:match('apiSecret.-"')
local reg67 = b:match('APISECRET.-"')
local reg68 = b:match('api_key.-"')
local reg69 = b:match('API_KEY.-"')
local reg70 = b:match('api_secret.-"')
local reg71 = b:match('API_SECRET.-"')
local reg72 = b:match('apidocs.-"')
local reg73 = b:match('APIDOCS.-"')
local reg74 = b:match('app_key.-"')
local reg75 = b:match('APP_KEY.-"')

--exgrep (appkeysecret|APPKEYSECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (application_key|APPLICATION_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (appsecret|APPSECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (appspot|APPSPOT)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (auth|AUTH)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (auth_token|AUTH_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (authorizationToken|AUTHORIZATIONTOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (aws_access|AWS_ACCESS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (aws_access_key_id|AWS_ACCESS_KEY_ID)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (aws_key|AWS_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (aws_secret|AWS_SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]7} (aws_token|AWS_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} 
local reg76 = b:match('APPKEYSECRET.-"')
local reg77 = b:match('application_key.-"')
local reg78 = b:match('APPLICATION_KEY.-"')
local reg79 = b:match('appsecret.-"')
local reg80 = b:match('APPSECRET.-"')
local reg81 = b:match('appspot.-"')
local reg82 = b:match('APPSPOT.-"')
local reg83 = b:match('auth.-"')
local reg84 = b:match('AUTH.-"')
local reg85 = b:match('auth_token.-"')
local reg86 = b:match('AUTH_TOKEN.-"')
local reg85 = b:match('authorizationToken.-"')
local reg86 = b:match('AUTHORIZATIONTOKEN.-"')
local reg87 = b:match('aws_access.-"')
local reg88 = b:match('AWS_ACCESS.-"')
local reg89 = b:match('aws_access_key_id.-"')
local reg90 = b:match('AWS_ACCESS_KEY_ID.-"')
local reg91 = b:match('aws_key.-"')
local reg92 = b:match('AWS_KEY.-"')
local reg93 = b:match('aws_secret.-"')
local reg94 = b:match('AWS_SECRET.-"')
local reg95 = b:match('aws_token.-"')
local reg96 = b:match('AWS_TOKEN.-"')

--exgrep (bashrcpassword|BASHRCPASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (bucket_password|BUCKET_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (client_secret|CLIENT_SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (cloudfront|CLOUDFRONT)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (codecov_token|CODECOV_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (config|CONFIG)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (conn.login|CONN.LOGIN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (connectionstring|CONNECTIONSTRING)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (consumer_key|CONSUMER_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (credentials|CREDENTIALS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} 
local reg97 = b:match('bashrcpassword.-"')
local reg98 = b:match('BASHRCPASSWORD.-"')
local reg99 = b:match('bucket_password.-"')
local reg100 = b:match('BUCKET_PASSWORD.-"')
local reg101 = b:match('client_secret.-"')
local reg102 = b:match('CLIENT_SECRET.-"')
local reg103 = b:match('cloudfront.-"')
local reg104 = b:match('CLOUDFRONT.-"')
local reg105 = b:match('codecov_token.-"')
local reg106 = b:match('CODECOV_TOKEN.-"')
local reg107 = b:match('config.-"')
local reg108 = b:match('CONFIG.-"')
local reg109 = b:match('conn.login.-"')
local reg110 = b:match('CONN.LOGIN.-"')
local reg111 = b:match('connectionstring.-"')
local reg112 = b:match('CONNECTIONSTRING.-"')
local reg113 = b:match('consumer_key.-"')
local reg114 = b:match('CONSUMER_KEY.-"')
local reg115 = b:match('credentials.-"')
local reg116 = b:match('CREDENTIALS.-"')

--exgrep (database_password|DATABASE_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (db_password|DB_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (db_username|DB_USERNAME)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (dbpasswd|DBPASSWD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (dbpassword|DBPASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (dbuser|DBUSER)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{3} (dot-files|DOT-FILES)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (dotfiles|DOTFILES)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (encryption_key|ENCRYPTION_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (fabricApiSecret|FABRICAPISECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} 
local reg117 = b:match('database_password.-"')
local reg118 = b:match('DATABASE_PASSWORD.-"')
local reg119 = b:match('db_password.-"')
local reg120 = b:match('DB_PASSWORD.-"')
local reg121 = b:match('db_username.-"')
local reg122 = b:match('DB_USERNAME.-"')
local reg123 = b:match('dbpasswd.-"')
local reg124 = b:match('DBPASSWD.-"')
local reg125 = b:match('dbpassword.-"')
local reg126 = b:match('DBPASSWORD.-"')
local reg127 = b:match('dbuser.-"')
local reg128 = b:match('DBUSER.-"')
local reg129 = b:match('dot-files.-"')
local reg130 = b:match('DOT-FILES.-"')
local reg131 = b:match('encryption_key.-"')
local reg132 = b:match('ENCRYPTION_KEY.-"')
local reg133 = b:match('fabricApiSecret.-"')
local reg134 = b:match('FABRICAPISECRET.-"')

--exgrep (fb_secret|FB_SECRET)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (firebase|FIREBASE)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (ftp|FTP)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (gh_token|GH_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (github_key|GITHUB_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (github_token|GITHUB_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (gitlab|GITLAB)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (gmail_password|GMAIL_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (gmail_username|GMAIL_USERNAME)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (api.googlemapsAIza|API.GOOGLEMAPSAIZA)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} 
local reg135 = b:match('fb_secret.-"')
local reg136 = b:match('FB_SECRET.-"')
local reg137 = b:match('firebase.-"')
local reg138 = b:match('FIREBASE.-"')
local reg139 = b:match('ftp.-"')
local reg140 = b:match('FTP.-"')
local reg141 = b:match('gh_token.-"')
local reg142 = b:match('GH_TOKEN.-"')
local reg143 = b:match('github_key.-"')
local reg144 = b:match('GITHUB_KEY.-"')
local reg145 = b:match('github_token.-"')
local reg146 = b:match('GITHUB_TOKEN.-"')
local reg147 = b:match('gitlab.-"')
local reg148 = b:match('GITLAB.-"')
local reg149 = b:match('gmail_password.-"')
local reg150 = b:match('GMAIL_PASSWORD.-"')
local reg151 = b:match('gmail_username.-"')
local reg152 = b:match('GMAIL_USERNAME.-"')
local reg153 = b:match('api.googlemapsAIza.-"')
local reg154 = b:match('API.GOOGLEMAPSAIZA.-"')

--exgrep (herokuapp|HEROKUAPP)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (internal|INTERNAL)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (irc_pass|IRC_PASS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (key|KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (keyPassword|KEYPASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (ldap_password|LDAP_PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (ldap_username|LDAP_USERNAME)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (login|LOGIN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (mailchimp|MAILCHIMP)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (mailgun|MAILGUN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} 
local reg155 = b:match('herokuapp.-"')
local reg156 = b:match('HEROKUAPP.-"')
local reg157 = b:match('internal.-"')
local reg158 = b:match('INTERNAL.-"')
local reg159 = b:match('KEY.-"')
local reg160 = b:match('analytics.load(".-"')
local reg161 = b:match('keyPassword.-"')
local reg162 = b:match('KEYPASSWORD.-"')
local reg163 = b:match('ldap_password.-"')
local reg164 = b:match('LDAP_PASSWORD.-"')
local reg165 = b:match('ldap_username.-"')
local reg166 = b:match('LDAP_USERNAME.-"')
local reg167 = b:match('login.-"')
local reg168 = b:match('LOGIN.-"')
local reg169 = b:match('mailchimp.-"')
local reg170 = b:match('MAILCHIMP.-"')
local reg171 = b:match('mailgun.-"')
local reg172 = b:match('MAILGUN.-"')

--exgrep (master_key|MASTER_KEY)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (mydotfiles|MYDOTFILES)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (mysql|MYSQL)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (node_env|NODE_ENV)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (npmrc_auth|NPMRC_AUTH)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (oauth_token|OAUTH_TOKEN)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (pass|PASS)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (passwd|PASSWD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (password|PASSWORD)(:|=| : | = )( |"|')[0-9A-Za-z\\-]{5,100} (passwords|PASSWORDS)(:|=| : | 
local reg173 = b:match('master_key.-"')
local reg174 = b:match('MASTER_KEY.-"')
local reg175 = b:match('mydotfiles.-"')
local reg176 = b:match('MYDOTFILES.-"')
local reg177 = b:match('mysql.-"')
local reg178 = b:match('MYSQL.-"')
local reg179 = b:match('node_env.-"')
local reg180 = b:match('NODE_ENV.-"')
local reg181 = b:match('npmrc_auth.-"')
local reg182 = b:match('NPMRC_AUTH.-"')
local reg183 = b:match('oauth_token.-"')
local reg184 = b:match('OAUTH_TOKEN.-"')
local reg185 = b:match('pass.-"')
local reg186 = b:match('PASS.-"')
local reg187 = b:match('Passwd.-"')
local reg188 = b:match('PASSWD.-"')
local reg189 = b:match('password.-"')
local reg190 = b:match('PASSWORD.-"')
local reg191 = b:match('passwords.-"')
local reg192 = b:match('PASSWORDS.-"')

if reg1 ~= nil then
print("\n\n")
print("Leak 1")
print(reg1)
print("\n\n")
end
if reg2 ~= nil then
print("\n\n")
print("Leak 2")
print(reg2)
print("\n\n")
end
if reg3 ~= nil then
print("\n\n")
print("Leak 3")
print(reg3)
print("\n\n")
end
if reg4 ~= nil then
print("\n\n")
print("Leak 4")
print(reg4)
print("\n\n")
end
if reg5 ~= nil then
print("\n\n")
print("Leak 5")
print(reg5)
print("\n\n")
end
if reg6 ~= nil then
print("\n\n")
print("Leak 6")
print(reg6)
print("\n\n")
end
if reg7 ~= nil then
print("\n\n")
print("Leak 7")
print(reg7)
print("\n\n")
end
if reg8 ~= nil then
print("\n\n")
print("Leak 8")
print(reg8)
print("\n\n")
end
if reg9 ~= nil then
print("\n\n")
print("Leak 9")
print(reg9)
print("\n\n")
end
if reg10 ~= nil then
print("\n\n")
print("Leak 10")
print(reg10)
print("\n\n")
end
if reg11 ~= nil then
print("\n\n")
print("Leak 11")
print(reg11)
print("\n\n")
end
if reg12 ~= nil then
print("\n\n")
print("Leak 12")
print(reg12)
print("\n\n")
end
if reg13 ~= nil then
print("\n\n")
print("Leak 13")
print(reg13)
print("\n\n")
end
if reg14 ~= nil then
print("\n\n")
print("Leak 14")
print(reg14)
print("\n\n")
end
if reg15 ~= nil then
print("\n\n")
print("Leak 15")
print(reg15)
print("\n\n")
end
if reg16 ~= nil then
print("\n\n")
print("Leak 16")
print(reg16)
print("\n\n")
end
if reg17 ~= nil then
print("\n\n")
print("Leak 17")
print(reg17)
print("\n\n")
end
if reg18 ~= nil then
print("\n\n")
print("Leak 18")
print(reg18)
print("\n\n")
end
if reg19 ~= nil then
print("\n\n")
print("Leak 19")
print(reg19)
print("\n\n")
end
if reg20 ~= nil then
print("\n\n")
print("Leak 20")
print(reg20)
print("\n\n")
end
if reg21 ~= nil then
print("\n\n")
print("Leak 21")
print(reg21)
print("\n\n")
end
if reg22 ~= nil then
print("\n\n")
print("Leak 22")
print(reg22)
print("\n\n")
end
if reg23 ~= nil then
print("\n\n")
print("Leak 23")
print(reg23)
print("\n\n")
end
if reg24 ~= nil then
print("\n\n")
print("Leak 24")
print(reg24)
print("\n\n")
end
if reg25 ~= nil then
print("\n\n")
print("Leak 25")
print(reg25)
print("\n\n")
end
if reg26 ~= nil then
print("\n\n")
print("Leak 26")
print(reg26)
print("\n\n")
end
if reg27 ~= nil then
print("\n\n")
print("Leak 27")
print(reg27)
print("\n\n")
end
if reg28 ~= nil then
print("\n\n")
print("Leak 28")
print(reg28)
print("\n\n")
end
if reg29 ~= nil then
print("\n\n")
print("Leak 29")
print(reg29)
print("\n\n")
end
if reg30 ~= nil then
print("\n\n")
print("Leak 30")
print(reg30)
print("\n\n")
end
if reg31 ~= nil then
print("\n\n")
print("Leak 31")
print(reg31)
print("\n\n")
end
if reg32 ~= nil then
print("\n\n")
print("Leak 32")
print(reg32)
print("\n\n")
end

if reg38 ~= nil then
print("\n\n")
print("Leak 38")
print(reg38)
print("\n\n")
end
if reg39 ~= nil then
print("\n\n")
print("Leak 39")
print(reg39)
print("\n\n")
end
if reg40 ~= nil then
print("\n\n")
print("Leak 40")
print(reg40)
print("\n\n")
end
if reg41 ~= nil then
print("\n\n")
print("Leak 41")
print(reg41)
print("\n\n")
end
if reg42 ~= nil then
print("\n\n")
print("Leak 42")
print(reg42)
print("\n\n")
end
if reg43 ~= nil then
print("\n\n")
print("Leak 43")
print(reg43)
print("\n\n")
end
if reg44 ~= nil then
print("\n\n")
print("Leak 44")
print(reg44)
print("\n\n")
end
if reg45 ~= nil then
print("\n\n")
print("Leak 45")
print(reg45)
print("\n\n")
end
if reg46 ~= nil then
print("\n\n")
print("Leak 46")
print(reg46)
print("\n\n")
end
if reg47 ~= nil then
print("\n\n")
print("Leak 47")
print(reg47)
print("\n\n")
end
if reg48 ~= nil then
print("\n\n")
print("Leak 48")
print(reg48)
print("\n\n")
end
if reg49 ~= nil then
print("\n\n")
print("Leak 49")
print(reg49)
print("\n\n")
end
if reg50 ~= nil then
print("\n\n")
print("Leak 50")
print(reg50)
print("\n\n")
end
if reg51 ~= nil then
print("\n\n")
print("Leak 51")
print(reg51)
print("\n\n")
end
if reg52 ~= nil then
print("\n\n")
print("Leak 52")
print(reg52)
print("\n\n")
end
if reg53 ~= nil then
print("\n\n")
print("Leak 53")
print(reg53)
print("\n\n")
end
if reg54 ~= nil then
print("\n\n")
print("Leak 54")
print(reg54)
print("\n\n")
end
if reg55 ~= nil then
print("\n\n")
print("Leak 55")
print(reg55)
print("\n\n")
end
if reg56 ~= nil then
print("\n\n")
print("Leak 56")
print(reg56)
print("\n\n")
end
if reg57 ~= nil then
print("\n\n")
print("Leak 57")
print(reg57)
print("\n\n")
end
if reg58 ~= nil then
print("\n\n")
print("Leak 58")
print(reg58)
print("\n\n")
end
if reg59 ~= nil then
print("\n\n")
print("Leak 59")
print(reg59)
print("\n\n")
end
if reg60 ~= nil then
print("\n\n")
print("Leak 60")
print(reg60)
print("\n\n")
end
if reg61 ~= nil then
print("\n\n")
print("Leak 61")
print(reg61)
print("\n\n")
end
if reg62 ~= nil then
print("\n\n")
print("Leak 62")
print(reg62)
print("\n\n")
end
if reg63 ~= nil then
print("\n\n")
print("Leak 63")
print(reg63)
print("\n\n")
end
if reg64 ~= nil then
print("\n\n")
print("Leak 64")
print(reg64)
print("\n\n")
end
if reg65 ~= nil then
print("\n\n")
print("Leak 65")
print(reg65)
print("\n\n")
end
if reg66 ~= nil then
print("\n\n")
print("Leak 66")
print(reg66)
print("\n\n")
end
if reg67 ~= nil then
print("\n\n")
print("Leak 67")
print(reg67)
print("\n\n")
end
if reg68 ~= nil then
print("\n\n")
print("Leak 68")
print(reg68)
print("\n\n")
end
if reg69 ~= nil then
print("\n\n")
print("Leak 69")
print(reg64)
print("\n\n")
end
if reg70 ~= nil then
print("\n\n")
print("Leak 70")
print(reg70)
print("\n\n")
end
if reg71 ~= nil then
print("\n\n")
print("Leak 71")
print(reg71)
print("\n\n")
end
if reg72 ~= nil then
print("\n\n")
print("Leak 72")
print(reg72)
print("\n\n")
end
if reg73 ~= nil then
print("\n\n")
print("Leak 73")
print(reg73)
print("\n\n")
end
if reg74 ~= nil then
print("\n\n")
print("Leak 74")
print(reg74)
print("\n\n")
end
if reg75 ~= nil then
print("\n\n")
print("Leak 75")
print(reg75)
print("\n\n")
end
if reg76 ~= nil then
print("\n\n")
print("Leak 76")
print(reg76)
print("\n\n")
end
if reg77 ~= nil then
print("\n\n")
print("Leak 77")
print(reg77)
print("\n\n")
end
if reg78 ~= nil then
print("\n\n")
print("Leak 78")
print(reg78)
print("\n\n")
end
if reg79 ~= nil then
print("\n\n")
print("Leak 79")
print(reg79)
print("\n\n")
end
if reg80 ~= nil then
print("\n\n")
print("Leak 80")
print(reg80)
print("\n\n")
end
if reg81 ~= nil then
print("\n\n")
print("Leak 81")
print(reg81)
print("\n\n")
end
if reg82 ~= nil then
print("\n\n")
print("Leak 82")
print(reg82)
print("\n\n")
end
if reg83 ~= nil then
print("\n\n")
print("Leak 83")
print(reg83)
print("\n\n")
end
if reg84 ~= nil then
print("\n\n")
print("Leak 84")
print(reg84)
print("\n\n")
end
if reg85 ~= nil then
print("\n\n")
print("Leak 85")
print(reg85)
print("\n\n")
end
if reg86 ~= nil then
print("\n\n")
print("Leak 86")
print(reg86)
print("\n\n")
end
if reg87 ~= nil then
print("\n\n")
print("Leak 87")
print(reg87)
print("\n\n")
end
if reg88 ~= nil then
print("\n\n")
print("Leak 88")
print(reg88)
print("\n\n")
end
if reg89 ~= nil then
print("\n\n")
print("Leak 89")
print(reg89)
print("\n\n")
end
if reg90 ~= nil then
print("\n\n")
print("Leak 90")
print(reg90)
print("\n\n")
end
if reg91 ~= nil then
print("\n\n")
print("Leak 91")
print(reg91)
print("\n\n")
end
if reg92 ~= nil then
print("\n\n")
print("Leak 92")
print(reg92)
print("\n\n")
end
if reg93 ~= nil then
print("\n\n")
print("Leak 93")
print(reg93)
print("\n\n")
end
if reg94 ~= nil then
print("\n\n")
print("Leak 94")
print(reg94)
print("\n\n")
end
if reg95 ~= nil then
print("\n\n")
print("Leak 95")
print(reg95)
print("\n\n")
end
if reg96 ~= nil then
print("\n\n")
print("Leak 96")
print(reg96)
print("\n\n")
end
if reg97 ~= nil then
print("\n\n")
print("Leak 97")
print(reg97)
print("\n\n")
end
if reg98 ~= nil then
print("\n\n")
print("Leak 98")
print(reg98)
print("\n\n")
end
if reg99 ~= nil then
print("\n\n")
print("Leak 99")
print(reg90)
print("\n\n")
end
if reg100 ~= nil then
print("\n\n")
print("Leak 100")
print(reg100)
print("\n\n")
end
if reg101 ~= nil then
print("\n\n")
print("Leak 101")
print(reg101)
print("\n\n")
end
if reg102 ~= nil then
print("\n\n")
print("Leak 102")
print(reg102)
print("\n\n")
end
if reg103 ~= nil then
print("\n\n")
print("Leak 103")
print(reg103)
print("\n\n")
end
if reg104 ~= nil then
print("\n\n")
print("Leak 104")
print(reg104)
print("\n\n")
end
if reg105 ~= nil then
print("\n\n")
print("Leak 105")
print(reg105)
print("\n\n")
end
if reg106 ~= nil then
print("\n\n")
print("Leak 106")
print(reg106)
print("\n\n")
end
if reg107 ~= nil then
print("\n\n")
print("Leak 107")
print(reg107)
print("\n\n")
end
if reg108 ~= nil then
print("\n\n")
print("Leak 108")
print(reg108)
print("\n\n")
end
if reg109 ~= nil then
print("\n\n")
print("Leak 109")
print(reg109)
print("\n\n")
end
if reg110 ~= nil then
print("\n\n")
print("Leak 110")
print(reg110)
print("\n\n")
end
if reg111 ~= nil then
print("\n\n")
print("Leak 111")
print(reg111)
print("\n\n")
end
if reg112 ~= nil then
print("\n\n")
print("Leak 112")
print(reg112)
print("\n\n")
end
if reg113 ~= nil then
print("\n\n")
print("Leak 113")
print(reg113)
print("\n\n")
end
if reg114 ~= nil then
print("\n\n")
print("Leak 114")
print(reg114)
print("\n\n")
end
if reg113 ~= nil then
print("\n\n")
print("Leak 113")
print(reg113)
print("\n\n")
end
if reg115 ~= nil then
print("\n\n")
print("Leak 115")
print(reg115)
print("\n\n")
end
if reg116 ~= nil then
print("\n\n")
print("Leak 116")
print(reg116)
print("\n\n")
end
if reg117 ~= nil then
print("\n\n")
print("Leak 117")
print(reg117)
print("\n\n")
end
if reg118 ~= nil then
print("\n\n")
print("Leak 118")
print(reg118)
print("\n\n")
end
if reg119 ~= nil then
print("\n\n")
print("Leak 119")
print(reg119)
print("\n\n")
end
if reg120 ~= nil then
print("\n\n")
print("Leak 120")
print(reg120)
print("\n\n")
end
if reg121 ~= nil then
print("\n\n")
print("Leak 121")
print(reg121)
print("\n\n")
end
if reg122 ~= nil then
print("\n\n")
print("Leak 122")
print(reg122)
print("\n\n")
end
if reg123 ~= nil then
print("\n\n")
print("Leak 123")
print(reg123)
print("\n\n")
end
if reg124 ~= nil then
print("\n\n")
print("Leak 124")
print(reg124)
print("\n\n")
end
if reg125 ~= nil then
print("\n\n")
print("Leak 125")
print(reg125)
print("\n\n")
end
if reg126 ~= nil then
print("\n\n")
print("Leak 126")
print(reg126)
print("\n\n")
end
if reg127 ~= nil then
print("\n\n")
print("Leak 127")
print(reg127)
print("\n\n")
end
if reg128 ~= nil then
print("\n\n")
print("Leak 128")
print(reg128)
print("\n\n")
end
if reg129 ~= nil then
print("\n\n")
print("Leak 129")
print(reg129)
print("\n\n")
end
if reg130 ~= nil then
print("\n\n")
print("Leak 130")
print(reg130)
print("\n\n")
end
if reg131 ~= nil then
print("\n\n")
print("Leak 131")
print(reg131)
print("\n\n")
end
if reg132 ~= nil then
print("\n\n")
print("Leak 132")
print(reg132)
print("\n\n")
end
if reg133 ~= nil then
print("\n\n")
print("Leak 133")
print(reg133)
print("\n\n")
end
if reg134 ~= nil then
print("\n\n")
print("Leak 134")
print(reg134)
print("\n\n")
end
if reg135 ~= nil then
print("\n\n")
print("Leak 135")
print(reg135)
print("\n\n")
end
if reg136 ~= nil then
print("\n\n")
print("Leak 136")
print(reg136)
print("\n\n")
end
if reg137 ~= nil then
print("\n\n")
print("Leak 137")
print(reg137)
print("\n\n")
end
if reg138 ~= nil then
print("\n\n")
print("Leak 138")
print(reg138)
print("\n\n")
end
if reg139 ~= nil then
print("\n\n")
print("Leak 139")
print(reg139)
print("\n\n")
end
if reg140 ~= nil then
print("\n\n")
print("Leak 140")
print(reg140)
print("\n\n")
end
if reg141 ~= nil then
print("\n\n")
print("Leak 141")
print(reg141)
print("\n\n")
end
if reg142 ~= nil then
print("\n\n")
print("Leak 142")
print(reg142)
print("\n\n")
end
if reg143 ~= nil then
print("\n\n")
print("Leak 143")
print(reg143)
print("\n\n")
end
if reg144 ~= nil then
print("\n\n")
print("Leak 144")
print(reg144)
print("\n\n")
end
if reg145 ~= nil then
print("\n\n")
print("Leak 145")
print(reg145)
print("\n\n")
end
if reg146 ~= nil then
print("\n\n")
print("Leak 146")
print(reg146)
print("\n\n")
end
if reg147 ~= nil then
print("\n\n")
print("Leak 147")
print(reg147)
print("\n\n")
end
if reg148 ~= nil then
print("\n\n")
print("Leak 148")
print(reg148)
print("\n\n")
end
if reg149 ~= nil then
print("\n\n")
print("Leak 149")
print(reg149)
print("\n\n")
end
if reg150 ~= nil then
print("\n\n")
print("Leak 150")
print(reg150)
print("\n\n")
end
if reg151 ~= nil then
print("\n\n")
print("Leak 151")
print(reg151)
print("\n\n")
end
if reg152 ~= nil then
print("\n\n")
print("Leak 152")
print(reg152)
print("\n\n")
end
if reg153 ~= nil then
print("\n\n")
print("Leak 153")
print(reg153)
print("\n\n")
end
if reg154 ~= nil then
print("\n\n")
print("Leak 154")
print(reg154)
print("\n\n")
end
if reg155 ~= nil then
print("\n\n")
print("Leak 155")
print(reg155)
print("\n\n")
end
if reg156 ~= nil then
print("\n\n")
print("Leak 156")
print(reg156)
print("\n\n")
end
if reg157 ~= nil then
print("\n\n")
print("Leak 157")
print(reg157)
print("\n\n")
end
if reg158 ~= nil then
print("\n\n")
print("Leak 158")
print(reg158)
print("\n\n")
end
if reg159 ~= nil then
print("\n\n")
print("Leak 159")
print(reg159)
print("\n\n")
end
if reg160 ~= nil then
print("\n\n")
print("Leak 160")
print(reg160)
print("\n\n")
end
if reg161 ~= nil then
print("\n\n")
print("Leak 161")
print(reg161)
print("\n\n")
end
if reg162 ~= nil then
print("\n\n")
print("Leak 162")
print(reg162)
print("\n\n")
end
if reg163 ~= nil then
print("\n\n")
print("Leak 163")
print(reg163)
print("\n\n")
end
if reg164 ~= nil then
print("\n\n")
print("Leak 164")
print(reg164)
print("\n\n")
end
if reg164 ~= nil then
print("\n\n")
print("Leak 165")
print(reg165)
print("\n\n")
end
if reg166 ~= nil then
print("\n\n")
print("Leak 166")
print(reg166)
print("\n\n")
end
if reg167 ~= nil then
print("\n\n")
print("Leak 167")
print(reg167)
print("\n\n")
end
if reg168 ~= nil then
print("\n\n")
print("Leak 168")
print(reg168)
print("\n\n")
end
if reg169 ~= nil then
print("\n\n")
print("Leak 169")
print(reg169)
print("\n\n")
end
if reg170 ~= nil then
print("\n\n")
print("Leak 170")
print(reg170)
print("\n\n")
end
if reg171 ~= nil then
print("\n\n")
print("Leak 171")
print(reg171)
print("\n\n")
end
if reg172 ~= nil then
print("\n\n")
print("Leak 172")
print(reg172)
print("\n\n")
end
if reg173 ~= nil then
print("\n\n")
print("Leak 173")
print(reg173)
print("\n\n")
end
if reg174 ~= nil then
print("\n\n")
print("Leak 174")
print(reg174)
print("\n\n")
end
if reg175 ~= nil then
print("\n\n")
print("Leak 175")
print(reg175)
print("\n\n")
end
if reg176 ~= nil then
print("\n\n")
print("Leak 176")
print(reg176)
print("\n\n")
end
if reg177 ~= nil then
print("\n\n")
print("Leak 177")
print(reg177)
print("\n\n")
end
if reg178 ~= nil then
print("\n\n")
print("Leak 178")
print(reg178)
print("\n\n")
end
if reg179 ~= nil then
print("\n\n")
print("Leak 179")
print(reg179)
print("\n\n")
end
if reg180 ~= nil then
print("\n\n")
print("Leak 180")
print(reg180)
print("\n\n")
end
if reg181 ~= nil then
print("\n\n")
print("Leak 181")
print(reg181)
print("\n\n")
end
if reg182 ~= nil then
print("\n\n")
print("Leak 182")
print(reg182)
print("\n\n")
end
if reg183 ~= nil then
print("\n\n")
print("Leak 183")
print(reg183)
print("\n\n")
end
if reg184 ~= nil then
print("\n\n")
print("Leak 184")
print(reg184)
print("\n\n")
end
if reg185 ~= nil then
print("\n\n")
print("Leak 185")
print(reg185)
print("\n\n")
end
if reg186 ~= nil then
print("\n\n")
print("Leak 186")
print(reg186)
print("\n\n")
end
if reg187 ~= nil then
print("\n\n")
print("Leak 187")
print(reg187)
print("\n\n")
end
if reg188 ~= nil then
print("\n\n")
print("Leak 188")
print(reg188)
print("\n\n")
end
if reg189 ~= nil then
print("\n\n")
print("Leak 189")
print(reg189)
print("\n\n")
end
if reg190 ~= nil then
print("\n\n")
print("Leak 190")
print(reg190)
print("\n\n")
end
if reg191 ~= nil then
print("\n\n")
print("Leak 191")
print(reg191)
print("\n\n")
end
if reg192 ~= nil then
print("\n\n")
print("Leak 192")
print(reg192)
print("\n\n")
end

print("#######################")

end

