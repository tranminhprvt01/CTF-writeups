from random import shuffle
from Crypto.Util.number import getPrime

FLAG = b'crew{fake_flag}'
assert len(FLAG) < 100

encoded_flag = []

for i, b in enumerate(FLAG):
    #print(i, b)
    encoded_flag.extend([i + 0x1337] * b)
    #print(encoded_flag)

shuffle(encoded_flag)

e = 65537
p, q = getPrime(1024), getPrime(1024)
n = p * q
c = sum(pow(m, e, n) for m in encoded_flag) % n



print(n)
print(e)
print(c)