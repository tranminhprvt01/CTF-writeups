from pwn import *
import base64
import hashlib
from Crypto.Util.number import *
from gmpy2 import iroot


HASH_ASN1 = {
        'MD5': b'\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10',
        'SHA-1': b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
        'SHA-256': b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
        'SHA-384': b'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
        'SHA-512': b'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40'
}


def h(msg, hsh):
    HASH_FUNC = {
            'MD5': hashlib.md5(msg).digest(),
            'SHA-1': hashlib.sha1(msg).digest(),
            'SHA-256': hashlib.sha256(msg).digest(),
            'SHA-384': hashlib.sha384(msg).digest(),
            'SHA-512': hashlib.sha512(msg).digest()
    }
    return HASH_FUNC[hsh]

io = remote("localhost", 2003)



io.recvuntil(b'Hash: ')
hsh = io.recvline().rstrip().decode()
prefix = HASH_ASN1[hsh]

print(hsh)

io.recvuntil(b'Modulus = ')
n = int(io.recvline().rstrip().decode())


msg = b'tranminhprvt01'

if n.bit_length() == 2048:
    print("right case")
else:
    print("try again")

payload = b'\x00\x01\x00' + prefix + h(msg, hsh)
print(len(payload))
payload = payload+b'a'*(256-len(payload))
c = bytes_to_long(payload)
sth = base64.b64encode(long_to_bytes(iroot(c, 3)[0]))

io.sendlineafter(b'Enter the message you want to verify: ', msg)

io.sendlineafter(b'Enter its base64 signature: ', sth)




io.interactive()