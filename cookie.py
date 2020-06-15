from hashlib import sha256
from base64 import b64encode

print("Give input")
x = input()
y = sha256(x.encode())
y = y.hexdigest()
final = x+":"+y
encoded = b64encode(final.encode('ascii'))
print(encoded.decode('ascii'))
