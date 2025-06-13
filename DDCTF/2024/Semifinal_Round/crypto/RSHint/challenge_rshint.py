from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import random

p = getPrime(512)
q = getPrime(512)
n = p*q
e = 65537
flag = b"flag{R3D4CT3D}"
c = pow(bytes_to_long(flag), e, n)

s = random.randint(100, 170)

hint = (p>>s) << s

print(f"{hint=}")
print(f"{n=}")
print(f"{c=}")