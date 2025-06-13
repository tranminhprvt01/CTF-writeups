from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime
import random

e = 97
p = getPrime(512)
q = getPrime(512)
n = p * q

for j in range(2):
	a = random.getrandbits(512)
	b = random.getrandbits(512)
	flag = bytes_to_long(b"flag{R3D4CT3D}")
	ciphered_flag = pow(a*flag+b, e, n)
	print(f"c{j}={ciphered_flag}\na{j}={a}\nb{j}={b}\n{e=}\n{n=}")