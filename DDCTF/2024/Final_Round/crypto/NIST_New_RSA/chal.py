from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA
from mysecretutils import primegen

p, q = primegen(2048)

n = p*q
e = 65537
phi = (p-1) * (q-1)
d = pow(e, -1, phi)

key = RSA.construct((n, e, d))

with open('flag.txt', 'rb') as f:
    FLAG = f.read()

m = bytes_to_long(FLAG)
c = pow(m, e, n)

with open('pub.pem', 'wb') as f:
    f.write(key.public_key().export_key('PEM'))

with open('priv.pem', 'wb') as f:
    f.write(key.export_key('PEM'))

with open('flag.txt.enc', 'wb') as f:
    f.write(long_to_bytes(c))