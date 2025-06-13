m = 57983
#p = 29

def pop(s):
    return map(lambda x: ord(x)^42, s)

def butter(s):
    return map(lambda x: x*p%m, s)

def churn(s):
    l = list(map(lambda x: (x << 3), s))
    print(l)
    return " ".join(map(lambda x: "{:x}".format(x).upper(), l[16:] + l[:16]))




from Crypto.Util.number import *


l = '3FB60 4F510 42930 31058 DEA8 4A818 DEA8 1AA88 65AE0 1C590 17898 1C590 29170 3FB60 55D10 29170 42930 6A7D8 4C320 4F510 5FC0 193A0 4F510 2E288 29170 643F8 31058 6A7D8 4A818 1AA88 1AA88'.split()

l = [int(i, 16)>>3 for i in l]
l = l[15:] + l[:15]
print(l)

known = b'CYBORG'


p = l[0]*inverse(known[0]^42, m) % m
print(p)

flag = []

for i in l:
    flag.append((i*inverse(p, m) % m)^42)

print(bytes(flag))



