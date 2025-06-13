from Crypto.PublicKey import RSA
from Crypto.Util.number import *

f = open('pub.pem', 'r')
key = RSA.importKey(f.read())

print(key.n, int(key.n).bit_length())
print(key.e)


n = key.n
e = key.e



c = open('flag.txt.enc', 'rb').read()

c = bytes_to_long(c)




from gmpy2 import iroot
from Crypto.Util.number import *


for x in range(2, 512):
    for y in range(1024):
        b1, b2 = 2**x + y, -2**x + y
        delta1, delta2 = b1**2 + 4*n, b2**2 + 4*n
        if iroot(delta1, 2)[1]:
            print(f'1 {x = } {y = } ')
        if iroot(delta2, 2)[1]:
            print(f'2 {x = } {y = } ')
            
x = 483
y = 576
b2 = -2**x + y
delta2 = b2 ** 2 + 4 * n
p = (-b2 + iroot(delta2, 2)[0]) // 2
q = n // p

d = pow(e, -1, (p - 1) * (q - 1))
m = pow(int(c), d, n)
print(long_to_bytes(int(m)))
