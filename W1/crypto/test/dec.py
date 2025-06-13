from hashlib import sha512
from Crypto.Cipher import ChaCha20
from Crypto.Util.number import *

def decrypt(key:bytes, ct:bytes):
    key = sha512(key).digest()
    nonce = key[32:32+8]
    key = key[:32]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(ct)


key = bytes.fromhex('3c54f90f4d2cc9c0b62df2866c2b4f0c5afae8136d2a1e76d2694999624325f5609c50b4677efa21a37664b50cec92c0')
ct = b'\xf2r\xd5L1\x86\x0f'
print(len(ct))
print(decrypt(key, ct))