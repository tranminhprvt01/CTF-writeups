from Crypto.Util.number import bytes_to_long, getPrime, inverse, isPrime
import random

nbits = 1024
p = getPrime(nbits // 2)
q = bytes_to_long(open('flag.txt', 'rb').read().strip() + random.randbytes(26))

assert q.bit_length() <= 512

while not isPrime(q):
    q += 1

n = p * q
e = 0x10001 
phi = (p-1)*(q-1)
d = inverse(e, phi)
dp = inverse(e, p - 1)
dq = inverse(e, q - 1)

def enc(m):
    m = bytes_to_long(m)
    c = pow(m, e, n)
    return c

m = b'The quick brown fox jumps over the lazy dog and I like dragons'
c = enc(m)

with open('out.txt', 'w') as f:
    f.write(f'{e = }\n')
    f.write(f'{d = }\n')
    f.write(f'{c = }\n')
    f.write(f'{n = }\n')