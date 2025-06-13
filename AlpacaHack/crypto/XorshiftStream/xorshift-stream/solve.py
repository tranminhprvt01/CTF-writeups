import os
import secrets
from Crypto.Util.strxor import strxor
import struct


def update_state(state):
    state = (state^(state << 13)) % 2**64
    state = (state^(state >> 7)) % 2**64
    state = (state^(state << 17)) % 2**64
    return state


enc = '142d35c86db4e4bb82ca5965ca1d6bd55c0ffeb35c8a5825f00819821cd775c4c091391f5eb5671b251f5722f1b47e539122f7e5eadc00eee8a6a631928a0c14c57c7e05b6575067c336090f85618c8e181eeddbb3c6e177ad0f9b16d23c777b313e62b877148f06014e8bf3bc156bf88eedd123ba513dfd6fcb32446e41a5b719412939f5b98ffd54c2b5e44f4f7a927ecaff337cddf19fa4e38cbe01162a1b54bb43b0678adf2801d893655a74c656779f9a807c3125b5a30f4800a8'
key_len = (len(enc)//3)*2
enc_key = enc[:key_len]
enc_flag = enc[key_len:]



from z3 import *

a = BitVec('a', 64)
b = []


#challenge take 8 bytes (in hex form) -> encrypt into another 8 bytes
for i in range(len(enc_key)//(8*2)):
    n = struct.unpack('<Q', bytes.fromhex(enc_key[i*(8*2):(i+1)*8*2]))[0] #convert to byte -> then to number in little endian format
    print(n)
    print(enc_key[i*(8*2):(i+1)*8*2], i)
    b.append(BitVecVal(n, 64))

print(b)

s = Solver()

for r in range(len(b)):
    t = a
    #print(t, r)
    for _ in range(r+1):
        t = t^(t<<13)
        t = t^LShR(t, 7)
        t = t^(t<<17)
    #print(t, "what")
    c = t^b[r]
    #print(c)
    for i in range(8):
        byte_i = Extract(8*(i+1)-1, 8*i, c)
        #print(byte_i, i)
        s.add(Or(And(byte_i >= 0x30, byte_i <= 0x39), And(byte_i >= 0x61, byte_i <= 0x66)))

print(s.check())
print(s.model())

init_state = s.model()[a].as_long()
print(init_state)



#Reconstruct
state = init_state
plain = b''

for i in range(0, len(enc), 8*2):
    state = update_state(state)
    t = bytes.fromhex(enc[i:i+8*2]).ljust(8, b'\x00')
    print(t, len(t))

    block = struct.unpack('<Q', t)[0]
    plain += struct.pack('<Q', (block^state))

print(plain, len(plain))

plain = plain[:len(enc)//2]

key = (plain[:key_len//2])
print(key, len(key))
sth = plain[key_len//2:]
print(len(sth))

print(strxor(bytes.fromhex(key.decode()), sth))









