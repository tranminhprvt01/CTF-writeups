from Crypto.Cipher import AES
from Crypto.Util.number import *
from sympy.ntheory import discrete_log
from sympy.ntheory.modular import crt


p = 4170887899225220949299992515778389605737976266979828742347
c = 0x49545b7d5204bd639e299bc265ca987fb4b949c461b33759
g = 7
ct = bytes.fromhex("ae7d2e82a804a5a2dcbc5d5622c94b3e14f8c5a752a51326e42cda6d8efa4696")



primes = [2, 19, 151, 577, 67061, 18279232319, 111543376699, 9213409941746658353293481]

exp = [1, 1, 1, 1, 1, 1, 1, 1]

order1 = (p-1) // primes[-1]
order2 = (p-1) // order1

g1 = pow(g, order2, p)
c1 = pow(c, order2, p)

print("g1", g1)
print("c1", c1)

x1 = discrete_log(p, c1, g1)


print(x1, x1.bit_length())


print("~"*40)
print("this is ell", order2)

g2 = pow(g, order1, p)
c2 = pow(c, order1, p)

print("g2", g1)
print("c2", c1)

#using cado-nfs
log_c = 1607529382666405025125600
log_g = 8483029440103488262728827

x2 = log_c * inverse(log_g, order2) % order2
print(x2, x2.bit_length())
print("~"*40)

#now we use crt to recover key

res = crt([order1, order2], [x1, x2])
key = res[0]

print(key)
key = long_to_bytes(key)

flag = AES.new(key,AES.MODE_ECB).decrypt(ct)
print(flag)












