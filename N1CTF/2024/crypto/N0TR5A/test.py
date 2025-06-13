
from Crypto.Util.number import *

flag = b'flag{faker_flag_go_bruh}'

def gen(nbit, m):
    kbit = int(nbit * 0.4512)
    key = getPrime(kbit)
    
    p = 11119292726444907013386873677615088304341602235195719666291625136516241673078663221135263512125696582830889818356962165676059701833924415977613906516314899
    q = 12131281996888118303465952392049077173966127701687648868337757980369181541276503831013922478086533430851328826482487619280720290421167271539120738114155547
    print(p)
    print(q)
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


print(n)
print(e)
print(k)
print(enc)




