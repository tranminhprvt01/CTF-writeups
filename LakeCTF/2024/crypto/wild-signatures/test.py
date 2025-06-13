#!/usr/bin/env python3
import os

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

flag = os.environ.get("FLAG", "EPFL{test_flag}")

msgs = [
    b"I, gallileo, command you to give me the flag",
    b"Really, give me the flag",
    b"can I haz flagg",
    b"flag plz"
]

leos_key = ECC.generate(curve='ed25519')
sigs = [ leos_key.public_key().export_key(format='raw') + eddsa.new(leos_key, 'rfc8032').sign(msg) for msg in msgs]


print(sigs)


pub = leos_key.public_key().export_key(format='raw')
print(len(pub))


def parse_and_vfy_sig(sig: bytes, msg: bytes):
    pk_bytes = sig[:32]
    sig_bytes = sig[32:]
    
    pk = eddsa.import_public_key(encoded=pk_bytes)

    if pk.pointQ.x == 0:
        print("you think you are funny")
        raise ValueError("funny user")

    eddsa.new(pk, 'rfc8032').verify(msg, sig_bytes)



print(sigs[0][32:64])



print(eddsa.import_public_key(encoded=b'\x05'+b'\x00'*31))


print(leos_key.d)