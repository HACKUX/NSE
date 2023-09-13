local url = 'http://www.example.com'

local tabstr = {}
local strenc = ""
local str, str2
local n = string.len(url)
for i=1,n do
str = string.format("%%%02x",string.byte(url,i))
table.insert(tabstr, str)
end

for k,v in pairs(tabstr) do
strenc = strenc..v
end

local url_enc = strenc
print(url_enc)