from pwn import *
from Crypto.Util.number import *


DEATH_CAUSES = [
	'a fever',
	'dysentery',
	'measles',
	'cholera',
	'typhoid',
	'exhaustion',
	'a snakebite',
	'a broken leg',
	'a broken arm',
	'drowning',
]

io = remote("dicec.tf", 31001)

from tqdm import tqdm

for _ in tqdm(range(64)):

    io.recvuntil(b'n: ')
    n = int(io.recvline().rstrip().decode())

    io.recvuntil(b'e: ')
    e = int(io.recvline().rstrip().decode())


    io.recvuntil(b'x0: ')
    x0 = int(io.recvline().rstrip().decode())


    io.recvuntil(b'x1: ')
    x1 = int(io.recvline().rstrip().decode())


    # We have k0^e = (v-x0) and k1^e = (v-x1). At here, we want to make a relation between k0 and k1.
    # Therefore, say (v-x0) = t*(v-x1) => k0^e = t*k1^e. Lets say t = 2^e. We gonna have k0^e = (2*k1)^e. 
    # Take logarithm, we will have k0 = 2*k1. Which mean we now can calculate k0 from k1 and wiselike.
    # Now we want to solve for v in the previous equation. v = (x0-x1)*(1-t)^-1.
    # The reason to have a relation between k0 and k1 is for when we have c0 and c1
    # we will now bruteforce the `die` message to identify the other one. Hence, the `die` lists is small, is will be relatably fast

    t = pow(2, e, n)

    v = ((x0-t*x1) * inverse(1-t, n)) % n

    #print(v)

    io.sendlineafter(b'v: ', f'{v}')


    io.recvuntil(b'c0: ')
    c0 = int(io.recvline().rstrip().decode())


    io.recvuntil(b'c1: ')
    c1 = int(io.recvline().rstrip().decode())



    res = None

    for die in DEATH_CAUSES:
        m1 = int.from_bytes(f'you die of {die}.'.encode(), 'big')
        

        #m1 ~ k1 ~ c1 -> k0 = 2*k1

        k1 = (c1 - m1) % n
        k0 = (2*k1) % n
        m0 = (c0 - k0) % n
        #print(long_to_bytes(m0))

        try:
            res = long_to_bytes(m0).decode('utf-8')
            page_idx = res.index('turn to page ')
            assert all(i in '0123456789' for i in res[page_idx+13:-1])
            break
        except:
            pass
        
        
        #m1 ~ k0 ~ c0 -> k1 = k0*2^-1 
        k0 = (c0 - m1) % n
        k1 = (inverse(2, n)*k0) %n
        m0 = (c1 - k1) % n
        #print(long_to_bytes(m0))

        try:
            res = long_to_bytes(m0).decode('utf-8')
            page_idx = res.index('turn to page ')
            assert all(i in '0123456789' for i in res[page_idx+13:-1])
            break
        except:
            pass

        #print(res)

        #print("~"*20)


    page_idx = res.index('turn to page ')
    print(page_idx)
    page = res[page_idx+13:-1]
    print(page)

    io.sendlineafter(b'turn to page:', str(page))





io.interactive()


#  you find a chest containing dice{gl3am1ng_g0ld_doubl00n}