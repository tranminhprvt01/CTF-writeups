from Crypto.Util.number import *
from secret import flag

def gen(nbit, m):
    kbit = int(nbit * 0.4512)
    key = getPrime(kbit)
    
    while True:
        p = getPrime(nbit // 2 - 1)
        if isPrime(p * 2 + 1):
            p = p * 2 + 1
            break
    while True:
        q = getPrime(nbit // 2 - 1)
        if isPrime(q * 2 + 1):
            q = q * 2 + 1
            break   
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e, k = [], []
    for i in range(m):
        dd = key + 2 * i + 2
        ee = inverse(dd, phi)
        kk = (ee * dd - 1) // phi
        e.append(ee % 2 ** (nbit - kbit))
        k.append(kk)
    
    return n, e, k

n, e, k = gen(1024, 12)
enc = pow(bytes_to_long(flag), 65537, n)

with open("data.txt","w") as f:
    f.write(f"{n = }\n{enc = }\n{e = }\n{k = }\n")
