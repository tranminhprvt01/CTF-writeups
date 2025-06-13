from rrandom import randint
from hashlib import sha256
from sage.all import (
    EllipticCurve,
    gcd
)


class ECDSA:
    def __init__(self, curve: EllipticCurve, hashfunc=sha256, private=None):
        self.curve = curve
        self.gen = curve.gens()[0]
        self.hashfunc = hashfunc
        self.order = curve.order()
        if private is not None:
            self.private = private
        else:
            self.private = randint(1, self.order)
        self.public = self.private * self.gen

    def sign(self, message: bytes) -> (int, int):
        nonce = randint(1, self.order)
        if gcd(nonce, self.order) != 1:
            return self.sign(message)

        temp = nonce * self.gen
        r = int(temp.xy()[0])
        if r == 0:
            return self.sign(message)

        e = self.hashfunc(message).digest()
        e = int.from_bytes(e, 'big')
        s = pow(nonce, -1, self.order) * (e + r * self.private)
        s %= self.order
        if gcd(s, self.order) != 1:
            return self.sign(message)

        return r, s

    def verify(self, message: bytes, r: int, s: int) -> bool:
        if not 1 <= r <= self.order - 1:
            raise ValueError("Bad signature")
        if not 1 <= s <= self.order - 1:
            raise ValueError("Bad signature")
        e = self.hashfunc(message).digest()
        e = int.from_bytes(e, 'big')
        w = pow(s, -1, self.order)
        u1 = (e * w) % self.order
        u2 = (r * w) % self.order
        X = u1 * self.gen + u2 * self.public
        if X == self.curve.zero():
            return False

        v = int(X.xy()[0])
        return v == r

    def get_public(self) -> (int, int):
        return self.public.xy()
