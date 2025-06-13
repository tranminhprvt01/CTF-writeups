from pwn import *
from Crypto.Util.number import *
from sympy import primefactors




io = remote("krsa.ctf.intigriti.io", 1346)


io.recvuntil(b'n=')
n = int(io.recvline().rstrip().decode())
e = 0x10001
io.recvuntil(b'ck=')
ck = int(io.recvline().rstrip().decode())


"""
p = getPrime(1024)
q = getPrime(1024)

n = p*q
e = 0x10001

k = getRandomNBitInteger(32)
k_fac = primefactors(k)
ck = pow(k, e, n)


# treat k = a*b => k^e = a^e*b^e = ck => b^e = ck*a^-e % n

print(k)
print(k_fac, len(k_fac))
"""

a_ls = []
b_ls = []

from tqdm import tqdm

for i in tqdm(range(1, 2**18)):
    a_ls.append(((ck*pow(i, -e, n))%n, i))
    b_ls.append((pow(i, e, n), i))

print(len(a_ls))
print(len(b_ls))



a_ls = sorted(a_ls, key=lambda x: x[0])
b_ls = sorted(b_ls, key=lambda x: x[0])


a_dict = {x[0]: x[1] for x in a_ls}

# Find matching first values and print corresponding second elements
for i, j in b_ls:
    if i in a_dict:
        print(f"Matching value: {i}, a_ls second element: {a_dict[i]}, b_ls second element: {j}")
        print(j*a_dict[i])
        io.sendlineafter(b'Secret key ? ', str(j*a_dict[i]))
        io.interactive()
        


