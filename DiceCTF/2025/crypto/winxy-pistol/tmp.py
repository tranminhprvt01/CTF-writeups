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





io = remote("dicec.tf", 31002)

from tqdm import tqdm

for _ in tqdm(range(2)):

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