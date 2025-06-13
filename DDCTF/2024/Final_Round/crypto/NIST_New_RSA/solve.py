from Crypto.PublicKey import RSA

key = RSA.importKey(open('pub.pem','rb').read())

print(key.n, key.n.bit_length())
print(key.e)




from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl, inverse
from gmpy2 import mpz, powmod, next_prime, gcd, is_power, is_prime


n = key.n
e = key.e
c = btl(open("flag.txt.enc", 'rb').read())
print(c, c.bit_length())

#base convert n from 10 -> 13 and witness da magik
p = int('19a5a0b22c59964158356835c187688559b88649bcc2199aa6455718b494a53abb10506356b48bb1b00610490483a9a68b87c0a22733679260aca9b4c598c72b353a54173c8706235755caabb1b488c5abb8bb2987240886b72797568104835426c03a07279a', 13)
print(p)
print(gcd(p, n))
q = n//p

d = inverse(e, (p-1)*(q-1))

print(d)

print(ltb(pow(c, d, n)))
