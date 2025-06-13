import os
from rrandom import choices
from hashlib import sha256
from csidh import CSIDH, to_weierstrass
from ecdsa import ECDSA


FLAG = os.getenv('FLAG', 'flag{труляля}')


def captcha(complexity_hex=5):
    challenge = bytes(choices(range(256), k=complexity_hex)).hex()
    challenge = challenge[:complexity_hex]
    print(challenge)
    solution = bytes.fromhex(input().strip())
    solution = sha256(solution).hexdigest()
    if not solution.startswith(challenge):
        raise ValueError("Wrong captcha")


def task():
    captcha()
    alice = CSIDH()
    print(f"Alice key {alice.public_key}")
    bob = int(input("> "))
    shared = alice.exchange(bob)
    curve = to_weierstrass(shared)
    ecdsa = ECDSA(curve)
    print(ecdsa.get_public())
    # sanity check
    assert ecdsa.verify(b'amogus', *ecdsa.sign(b'amogus'))
    r = int(input("> "))
    s = int(input("> "))
    if ecdsa.verify(b'amogus', r, s):
        print(FLAG)
    else:
        print('Wrong')


if __name__ == "__main__":
    task()
