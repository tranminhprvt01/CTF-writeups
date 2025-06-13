from Crypto.Cipher import AES
import os
os.environ['PWNLIB_NOTERM'] = '1'
os.environ['TERM'] = 'xterm-256color'

from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad, unpad
import struct

R.<x> = PolynomialRing(GF(2), 'x')
GHASH_modulus = x^128 + x^7 + x^2 + x + 1
K = GF(2**128, name='a', modulus=GHASH_modulus)


def bytes_to_bit_array(data):
    bit_array = []
    for byte in data:
        bits = bin(byte)[2:].zfill(8)  
        bit_array.extend(map(int, bits))  
    return bit_array

def bit_array_to_bytes(bit_array):
    pad_length = len(bit_array) % 8
    if pad_length != 0:
        bit_array.extend([0] * (8 - pad_length))
    bytes_data = bytearray()
    for i in range(0, len(bit_array), 8):
        byte = 0
        for j in range(8):
            byte |= bit_array[i + j] << j
        bytes_data.append(byte)

    return bytes(bytes_data)


def encrypt_gcm(key, iv, pt,aad = None):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    if aad:
        cipher = cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(pt)
    return ct, tag
def decrypt_gcm(key, iv, ct, tag, aad = None):
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    if aad:
        cipher = cipher.update(aad)
    pt = cipher.decrypt_and_verify(ct, tag)
    return pt



def encrypt_ECB(key, pt):
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pt)
    return ct

def encrypt_EBC_nonce(key,pt,iv):
    cipher = AES.new(key, AES.MODE_ECB)
    key_expansion = cipher.encrypt(iv)
    ct = xor(pt,key_expansion)
    return ct


def bytes_to_field_element(byte_array):
    bin_arr = bytes_to_bit_array(byte_array)
    return K(bin_arr)

import time
def field_element_to_bytes(field_element):
    bit_array = field_element.polynomial().list()
    byte_data = bytearray()
    for i in range(0, len(bit_array), 8):
        bits = bit_array[i:i+8]
        byte_str = ''.join(str(bit) for bit in bits)
        byte = int(byte_str, 2)
        byte_data.append(byte)
    return bytes(byte_data)



def length_block(aad_length, ciphertext_length):
    aad_length_bits = aad_length * 8
    ciphertext_length_bits = ciphertext_length * 8
    
    # Pack the lengths into a byte array using big-endian format
    last_block = struct.pack('>QQ', aad_length_bits, ciphertext_length_bits)
    return last_block



def solve(message,TAG,aad=None):
    key = os.urandom(32)
    numberofblock = 0
    message = pad(message,16)
    numberofblock = numberofblock + len(message)//16
    iv = os.urandom(12)
    iv = bytes(iv)
    array_ct_fixed = []
    if aad:
        for i in range(0,len(aad),16):
            array_ct_fixed.append(aad[i:i+16])
    else :
        array_ct_fixed = []
    for i in range(2, numberofblock+2):
        ct = encrypt_EBC_nonce(key,message[(i-2)*16:(i-1)*16],iv+b'\x00'*3+bytes([i]))
        array_ct_fixed.append(ct)
    
    H1 = encrypt_ECB(key,b'\x00'*16)
    
    # nonce for T = iv||0^31||1
    T1 = encrypt_EBC_nonce(key,b'\x00'*16,iv+b'\x00'*3+b'\x01')

    LENBLOCK = length_block(0,len(message)+16) # 16 last append block :> 
    if aad:
        LENBLOCK = length_block(len(aad),len(message)+16) # 16 last append block :>
    LENBLOCK =bytes_to_field_element(LENBLOCK)
   
    H1 = bytes_to_field_element(H1)

    T1 = bytes_to_field_element(T1)
    array_ct = [bytes_to_field_element(i) for i in array_ct_fixed]

    TAG = bytes_to_field_element(TAG)
    LHS = H1^2
    RHS = sum([H1^(len(array_ct)-(i)+2)*array_ct[i] for i in range(len(array_ct))]) + (H1)*LENBLOCK + T1 
    
    # we have TAG = LHS*X + RHS
    Need_block = (TAG-RHS)*LHS^(-1)
    
    
    ciphertext_attack = iv
    if aad:
        array_ct = array_ct[len(aad)//16:]
    for i in range(0,len(array_ct)):
        ciphertext_attack += field_element_to_bytes(array_ct[i])
    ciphertext_attack += field_element_to_bytes(Need_block)
    ciphertext_attack += field_element_to_bytes(TAG)
    return key,ciphertext_attack
    


# io = process(['python3','chall.py'])
# print(io.recvuntil(b'tag: '))
# TAG = io.recvline().strip()
# TAG = bytes.fromhex(TAG.decode())
# print(io.recvuntil(b'aad: '))
# aad = io.recvline().strip()
# aad = bytes.fromhex(aad.decode())
# print(io.recvuntil(b'need_message: '))
# message = io.recvline().strip()
# message = bytes.fromhex(message.decode())


message = bytes.fromhex('97e6d5c425e6f7c30738e1f7f5adbafec101600c9726e7d78bc03ef430d0d1f8d778d0c991644876816e15c69faa6a3a0f0ec6153e4d54bd8697dd4f09ddd6db98bdacb4c44df105a011d187c0e709523dbbaf7224b7b5602d5f0ec6e45c4d6aec506ae0d36211ac52b9f807817cd9b6569222785b497dadcf90da552f788bea12d8379c013c6c967cae4fbb22a65562c84ec9f6018a8c680d155fb06083e5ec667776061deee12c0fc1476022142d4197cea3cc6c072f68f84ab5bf395ca9c2c301378cd3741253307a8fa27f59dec2e8d2c4b210c80e2ab38a761142f426079fcd0e3d3e72999db787d1b9f0e5e536075047a682285e897b80df7020dd5948d51e6adfc8bab81bc7a06667e133a4c985eff69ff57d3c7b8e48c0cca3715b4182c8f721967eb81913e9369a35158352aefb4aad517c7afb07306fa5fba1e361ba6baa2521')
tag = bytes.fromhex('4a86c1b3842857ad6fef88d9c08d2cdd')

key,ciphertext_attack = solve(message,tag)


print(key)
print(ciphertext_attack)

print(key.hex())
print(ciphertext_attack.hex())
