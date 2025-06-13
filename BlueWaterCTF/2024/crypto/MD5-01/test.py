import math
from hashlib import md5 as md5_real
from Crypto.Util.number import *


# MD5 Implementation from https://rosettacode.org/wiki/MD5/Implementation#Python
rotate_amounts = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                  5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

constants = [int(abs(math.sin(i+1)) * 2**32) & 0xFFFFFFFF for i in range(64)]

init_values = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

functions = 16*[lambda b, c, d: (b & c) | (~b & d)] + \
            16*[lambda b, c, d: (d & b) | (~d & c)] + \
            16*[lambda b, c, d: b ^ c ^ d] + \
            16*[lambda b, c, d: c ^ (~b | d)]

index_functions = 16*[lambda i: i] + \
                  16*[lambda i: (5*i + 1)%16] + \
                  16*[lambda i: (3*i + 5)%16] + \
                  16*[lambda i: (7*i)%16]

def left_rotate(x, amount):
    x &= 0xFFFFFFFF
    return ((x<<amount) | (x>>(32-amount))) & 0xFFFFFFFF

def md5(message):

    message = bytearray(message) #copy our input into a mutable buffer
    orig_len_in_bits = (8 * len(message)) & 0xffffffffffffffff
    message.append(0x80)
    while len(message)%64 != 56:
        message.append(0)
    message += orig_len_in_bits.to_bytes(8, byteorder='little')

    hash_pieces = init_values[:]

    for chunk_ofst in range(0, len(message), 64):
        a, b, c, d = hash_pieces
        chunk = message[chunk_ofst:chunk_ofst+64]
        for i in range(64):
            f = functions[i](b, c, d)
            g = index_functions[i](i)
            to_rotate = a + f + constants[i] + int.from_bytes(chunk[4*g:4*g+4], byteorder='little')
            new_b = (b + left_rotate(to_rotate, rotate_amounts[i])) & 0xFFFFFFFF
            a, b, c, d = d, new_b, b, c
        for i, val in enumerate([a, b, c, d]):
            hash_pieces[i] += val
            hash_pieces[i] &= 0xFFFFFFFF
    
    return sum(x<<(32*i) for i, x in enumerate(hash_pieces))



m1 = open('collision1.bin', 'rb').read() #696c6f7665796f7520b2c149bcb3cf11e827b1912d0eeca0176a54bc411ef5d4871e8f6fcecd17f9fd99800df0ac6691f5b5606c1ce63a188023ef7efe5b82c8d4fe12edc0eb3ae8513c262584457928afb49b0a6d4d4e411e5b8de1cb09b5c31e064be225f2281d34b166ae0a8cd36c4e2c7a63584672cc99f2e943542b6dea
m2 = open('collision2.bin', 'rb').read() #696c6f7665796f7520b3c149bcb3cf11e827b1912d0eeca0176a54bc411ef5d4871e8f6fcecd17f9fd99800df0ac6691f5b5606c1ce63a188023ef7efe5b82c8d4fe12edc0eb3ae8513b262584457928afb49b0a6d4d4e411e5b8de1cb09b5c31e064be225f2281d34b166ae0a8cd36c4e2c7a63584672cc99f2e943542b6dea

print(m1.hex())
print(m2.hex())

assert m1 != m2

print(len(m1), len(m2))

print(md5(m1))
print(md5(m2))

assert md5(m1) == md5(m2)



m1 = m1.hex()
m2 = m2.hex()


m1 = m1+"4848484848"
m2 = m2+"4848484848"


m1 = bytes.fromhex(m1)
m2 = bytes.fromhex(m2)


print(md5(m1))
print(md5(m2))




"""
from pwn import *

io = remote("md5-01.chal.perfect.blue", "1337")

io.sendlineafter(b'm1 > ', m1.hex())
io.sendlineafter(b'm2 > ', m2.hex())

io.interactive()
"""