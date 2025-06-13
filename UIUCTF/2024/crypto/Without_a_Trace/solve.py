from pwn import *
import numpy as np
from Crypto.Util.number import *
import random

res = []

coeff = [random.randint(1, 100) for _ in range(25)]
while len(set(coeff)) != len(coeff):
    coeff = [random.randint(1, 100) for _ in range(25)]


turn = 0
for _ in range(5):
    io = remote("without-a-trace.chal.uiuc.tf", 1337, ssl=True)


    for i in range(5):
        io.sendlineafter(f'[WAT] u{i+1} = '.encode(), f'{coeff[turn]}'.encode())
        turn+=1
        
    io.recvuntil(b'[WAT] Have fun: ')
    res.append(int(io.recvline().rstrip().decode()))
    io.close()



print(res)

res = np.matrix(res)

A = np.matrix([coeff[i:i+5] for i in range(0, len(coeff), 5)])

print(A)
print(res)


F = np.linalg.solve(A, res.transpose())
F = F.astype(np.int64)

print(F)



flag = b''
for i in F:
    flag+=long_to_bytes(int(i))

print(flag)




io.interactive()


#uiuctf{tr4c1ng_&&_mult5!}



""""
from itertools import permutations


def check(M):
    def sign(sigma):
        l = 0
        for i in range(5):
            for j in range(i + 1, 5):
                if sigma[i] > sigma[j]:
                    l += 1
        return (-1)**l

    res = 0
    for sigma in permutations([0,1,2,3,4]):
        curr = 1
        for i in range(5):
            curr *= M[sigma[i]][i]
        print(sigma, curr)
        res += sign(sigma) * curr
    return res



u1 = 2
u2 = 0
u3 = 0
u4 = 0
u5 = 0

M = [
    [u1, 0, 0, 0, 0],
    [0, u2, 0, 0, 0],
    [0, 0, u3, 0, 0],
    [0, 0, 0, u4, 0],
    [0, 0, 0, 0, u5]
]


res = 0

print(check(M))


FLAG = 'abcdeabcdefghij'

import numpy as np
from Crypto.Util.number import bytes_to_long


def fun(M):
    f = [bytes_to_long(bytes(FLAG[5*i:5*(i+1)], 'utf-8')) for i in range(5)]
    F = [
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
    ]
    for i in range(5):
        F[i][i] = f[i]

    try:
        R = np.matmul(F, M)
        print(R)
        print(np.trace(R))
        return np.trace(R)

    except:
        print("[WAT] You're trying too hard, try something simpler")
        return None



res = fun(M)
"""

