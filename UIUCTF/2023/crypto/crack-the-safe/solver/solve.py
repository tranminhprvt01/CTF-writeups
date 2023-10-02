from Crypto.Cipher import AES
from Crypto.Util.number import *

p = 4170887899225220949299992515778389605737976266979828742347
c = 0x49545b7d5204bd639e299bc265ca987fb4b949c461b33759
g = 7
ct = bytes.fromhex("ae7d2e82a804a5a2dcbc5d5622c94b3e14f8c5a752a51326e42cda6d8efa4696")


primes = [2, 19, 151, 577, 67061, 18279232319, 111543376699, 9213409941746658353293481]

exp = [1, 1, 1, 1, 1, 1, 1, 1]
print(primes)
print(exp)

order = (p-1) // primes[-1]


from sympy.ntheory import discrete_log

g_ = pow(g, primes[-1], p)
c_ = pow(c, primes[-1], p)

print(g)
print(c)

x = discrete_log(p, c_, g_)

print(x, x.bit_length())
print(order)

"""
key only 16*8 = 128 bits and we already have 109 bits
just brute force res

key = x mod (order) => key = x+k*order
"""

k=0
while True:
	candidate = x+k*order
	if k%10000 == 0: 
		print("current variable")
		print("k", k)
		print("candidate", candidate)
		print("~"*40)
	if pow(g, candidate, p) == c:
		print("Found key", candidate)
		print("k", k)
		key = candidate
		break
	k+=1	




print(key)
key = long_to_bytes(key)

flag = AES.new(key,AES.MODE_ECB).decrypt(ct)
print(flag)
		





