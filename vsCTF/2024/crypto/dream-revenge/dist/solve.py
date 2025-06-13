
from pwn import remote
from Crypto.Cipher import AES
from Crypto.Util.Padding import  unpad
from hashlib import sha256
import random


def invertStep(si, si227):
    # S[i] ^ S[i-227] == (((I[i] & 0x80000000) | (I[i+1] & 0x7FFFFFFF)) >> 1) ^ (0x9908b0df if I[i+1] & 1 else 0)
    X = si ^ si227
    # we know the LSB of I[i+1] because MSB of 0x9908b0df is set, we can see if the XOR has been applied
    mti1 = (X & 0x80000000) >> 31
    if mti1:
        X ^= 0x9908b0df
    # undo shift right
    X <<= 1
    # now recover MSB of state I[i]
    mti = X & 0x80000000
    # recover the rest of state I[i+1]
    mti1 += X & 0x7FFFFFFF
    return mti, mti1



def unshiftRight(x, shift):
    res = x
    for i in range(32):
        res = x ^ res >> shift
    return res

def unshiftLeft(x, shift, mask):
    res = x
    for i in range(32):
        res = x ^ (res << shift & mask)
    return res

def untemper(v):
    v = unshiftRight(v, 18)
    v = unshiftLeft(v, 15, 0xefc60000)
    v = unshiftLeft(v, 7, 0x9d2c5680)
    v = unshiftRight(v, 11)
    return v


def init_genrand(seed):
        MT = [0] * 624
        MT[0] = seed & 0xffffffff
        for i in range(1, 623+1): # loop over each element
            MT[i] = ((0x6c078965 * (MT[i-1] ^ (MT[i-1] >> 30))) + i) & 0xffffffff
        return MT

def recover_kj_from_Ji(ji, ji1, i):
    # ji => J[i]
    # ji1 => J[i-1]
    const = init_genrand(19650218)
    key = ji - (const[i] ^ ((ji1 ^ (ji1 >> 30))*1664525))
    key &= 0xffffffff
    # return K[j] + j
    return key

def recover_Ji_from_Ii(Ii, Ii1, i):
    # Ii => I[i]
    # Ii1 => I[i-1]
    ji = (Ii + i) ^ ((Ii1 ^ (Ii1 >> 30)) * 1566083941)
    ji &= 0xffffffff
    # return J[i]
    return ji

def recover_Kj_from_Ii(Ii, Ii1, Ii2, i):
    # Ii => I[i]
    # Ii1 => I[i-1]
    # Ii2 => I[i-2]
    # Ji => J[i]
    # Ji1 => J[i-1]
    Ji = recover_Ji_from_Ii(Ii, Ii1, i)
    Ji1 = recover_Ji_from_Ii(Ii1, Ii2, i-1)
    return recover_kj_from_Ji(Ji, Ji1, i)

def recover_seed(outputs):
    S = [untemper(output) for output in outputs]
    I_227_, I_228 = invertStep(S[0], S[4])
    I_228_, I_229 = invertStep(S[1], S[5])
    I_229_, I_230 = invertStep(S[2], S[6])
    I_230_, I_231 = invertStep(S[3], S[7])

    I_228 += I_228_
    I_229 += I_229_
    I_230 += I_230_

    seed_h = recover_Kj_from_Ii(I_230, I_229, I_228, 230) - 1
    seed_l1 = recover_Kj_from_Ii(I_231, I_230, I_229, 231)
    seed1 = (seed_h << 32) + seed_l1
    return seed1


io = remote("vsc.tf",5004)
outputs = []
io.sendlineafter(">>> ", "[0,1,2,3,227,228,229,230]")
for idx in range(8):
    outputs.append(int(io.recvline().strip().decode()))
print(outputs)
recovered_seed = recover_seed(outputs)

random.seed(recovered_seed)
for idx in range(624):
    rand_out = random.getrandbits(32)

key = random.getrandbits(256)
nonce = random.getrandbits(256)
enc_flag = bytes.fromhex(io.recvline().strip().decode())
cipher = AES.new(sha256(str(key).encode()).digest()[:16], AES.MODE_GCM, nonce=sha256(str(nonce).encode()).digest()[:16])
print(cipher.decrypt(enc_flag))