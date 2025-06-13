from sage.all import (
    EllipticCurve,
    GF,
    PolynomialRing,
    prime_range,
    prod,
    kronecker_symbol,
    is_square,
    sign
)
from timeout_decorator import timeout
from rrandom import choices, randint

# https://gist.github.com/y011d4/7b93a01f37c66aee2c27fd732126958a
# used for idekctf 2024
primes = list(prime_range(3, 41))
p = 4 * prod(primes) - 1
Fp = GF(p)


def from_weierstrass(EC):
    a, b = EC.a4(), EC.a6()
    F = EC.base_field()
    PR = PolynomialRing(F, name="z")
    z = PR.gens()[0]
    roots = (z**3 + a*z + b).roots()
    assert len(roots) > 0
    alpha = roots[0][0]
    s = (3*alpha**2 + a).sqrt() ** (-1)
    return -3 * (-1)**s.is_square() * alpha * s


def to_weierstrass(A):
    B = 1
    a = (3 - A**2) * pow(3 * B**2, -1, p)
    b = (2 * A**3 - 9 * A) * pow(27 * B**3, -1, p)
    return EllipticCurve(Fp, [a, b])


@timeout(10)
def group_action(pub, priv):
    es = priv.copy()
    A = pub
    assert len(es) == len(primes)
    EC = to_weierstrass(A)
    while True:
        if all(e == 0 for e in es):
            break
        x = Fp(randint(1, p-1))
        r = Fp(x ** 3 + A * x ** 2 + x)
        s = kronecker_symbol(r, p)
        assert (2 * is_square(r)) - 1 == s
        I = [i for i, e in enumerate(es) if sign(e) == s]
        if len(I) == 0:
            continue
        if s == -1:
            EC = EC.quadratic_twist()
        while True:
            tmp = EC.random_element()
            if not tmp.is_zero():
                break
        x = tmp.xy()[0]
        t = prod([primes[i] for i in I])
        P = EC.lift_x(x)
        assert (p + 1) % t == 0
        Q = ((p + 1) // t) * P
        for i in I:
            assert t % primes[i] == 0
            R = (t // primes[i]) * Q
            if R.is_zero():
                continue
            phi = EC.isogeny(R)
            EC = phi.codomain()
            Q = phi(Q)
            assert t % primes[i] == 0
            t = t // primes[i]
            es[i] -= s
        if s == -1:
            EC = EC.quadratic_twist()
    return from_weierstrass(EC)


class CSIDH:
    def __init__(self, private_key: list[int] | None = None):
        self.private_key = choices([-1, 1], k=len(primes))
        self.public_key = group_action(0, self.private_key)

    def exchange(self, other_pupbkey):
        return group_action(other_pupbkey, self.private_key)
