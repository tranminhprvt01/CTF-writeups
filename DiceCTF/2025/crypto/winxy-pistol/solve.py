from pwn import *
from Crypto.Util.number import *

import hashlib
from Crypto.Util.strxor import strxor


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


def encrypt(k, msg):
	key = k.to_bytes(1024//8, 'big')
	msg = msg.encode().ljust(64, b'\x00')
	pad = hashlib.shake_256(key).digest(len(msg))
	return strxor(pad, msg)


def decrypt(k, ct:bytes):
    assert len(ct) == 64
    key = k.to_bytes(1024//8, 'big')
    pad = hashlib.shake_256(key).digest(len(ct))
    return strxor(pad, ct).rstrip(b'\x00')


def check(s:bytes):
    try:
        assert s.startswith(b'you continue walking. ')
        s = s.rstrip(b'\x00').decode('utf-8')
        page_idx = s.index('turn to page ')
        page_num = s[page_idx+13:-1]
        assert all(i in '0123456789' for i in page_num)
        return True, page_num
    except:
        return False, -1
    

def check_conn(c0_, c1):
    for die in DEATH_CAUSES:
        dies  = f'you die of {die}.'
        H = strxor(c0_, dies.encode().ljust(64, b'\x00'))
        m1 = strxor(H, c1)
        #print(m1, check(m1))
        if check(m1)[0]:
            return True, check(m1)[1]
    return False, -1



def new_conn(v, x1):
    io_new = remote("dicec.tf", 31002)
    io_new.recvuntil(b'n: ')
    n = int(io_new.recvline().rstrip().decode())

    io_new.recvuntil(b'e: ')
    e = int(io_new.recvline().rstrip().decode())


    io_new.recvuntil(b'x0: ')
    x0_new = int(io_new.recvline().rstrip().decode())


    io_new.recvuntil(b'x1: ')
    x1_new = int(io_new.recvline().rstrip().decode())


    v = (v-x1+x0_new) % n

    #print(v)

    

    io_new.sendlineafter(b'v: ', f'{v}')


    io_new.recvuntil(b'c0: ')
    c0_new = bytes.fromhex(io_new.recvline().rstrip().decode())


    io_new.recvuntil(b'c1: ')
    c1_new = bytes.fromhex(io_new.recvline().rstrip().decode())

    io_new.close()

    return c0_new, c1_new



io = remote("dicec.tf", 31002)


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


    v = x0

    #print(v)

    io.sendlineafter(b'v: ', f'{v}')


    io.recvuntil(b'c0: ')
    c0 = bytes.fromhex(io.recvline().rstrip().decode())


    io.recvuntil(b'c1: ')
    c1 = bytes.fromhex(io.recvline().rstrip().decode())



    #print(c0.hex())

    m0 = decrypt(0, c0)
    print(m0)
    res = check(m0)
    if res[0]:
        io.sendlineafter(b'turn to page: ', res[1])
    else:
        print("manual decrypt")
        while True:
            c0_, c1_ = new_conn(v, x1)
            res2 = check_conn(c0_, c1)
            if res2[0]:
                break
            
        #print(c0_.hex(), c1_.hex())
        print(res2[1])
        io.sendlineafter(b'turn to page: ', res2[1])


io.interactive()


# you find a chest containing dice{lu5tr0us_j3wel_tr1nk3t}
