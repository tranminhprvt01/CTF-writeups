import os
from sage.all import *
set_random_seed(1337)
p = 18315300953692143461
k = 3
Fp = GF(p**k)
print(Fp)
a, b = Fp.random_element(), Fp.random_element()


print(a)
print(b)



flag = (os.getenv('flag') or 'crew{submit_this_if_desperate}').encode()
s = Fp.fetch_int(int.from_bytes(flag[len('crew{'):-len('}')], 'big'))


tmp = int.from_bytes(b'submit_this_if_desperate', 'big')
print(tmp, tmp%p, tmp//p % p, tmp//p**2 % p)

print(s, type(s))


out = []
for _ in range(12): 
    out.extend(s:=a*s+b)
print([x>>57 for x in out])

