from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import hashlib
import random

"""
p = getPrime(256)

A = random.randint(0, 2**256)
B = random.randint(0, 2**256)

E = EllipticCurve(GF(p), [A, B])

print(E)

"""

p = 91725037968177304595356229847249124275634668177296814741529573801095034173523
x1 = 70531110072509298803201621415592601393387767551616451246154013182556851771153
y1 = 3128592393207593101775747511252725036748347188549955655359151644135290113924
x2 = 58557423359848065299975326112549968009731308453890093788309799350030839061814
y2 = 75706164316220403423610626861470333353921225390662051210752341134842694488677

def attack(p, x1, y1, x2, y2):
    """
    Recovers the a and b parameters from an elliptic curve when two points are known.
    :param p: the prime of the curve base ring
    :param x1: the x coordinate of the first point
    :param y1: the y coordinate of the first point
    :param x2: the x coordinate of the second point
    :param y2: the y coordinate of the second point
    :return: a tuple containing the a and b parameters of the elliptic curve
    """
    a = pow(x1 - x2, -1, p) * (pow(y1, 2, p) - pow(y2, 2, p) - (pow(x1, 3, p) - pow(x2, 3, p))) % p
    b = (pow(y1, 2, p) - pow(x1, 3, p) - a * x1) % p
    return int(a), int(b)



a, b = attack(p, x1, y1, x2, y2)

E = EllipticCurve(GF(p), [a, b])

j_E = E.j_invariant()

print(j_E)


X=E(70531110072509298803201621415592601393387767551616451246154013182556851771153,3128592393207593101775747511252725036748347188549955655359151644135290113924)

Y=E(58557423359848065299975326112549968009731308453890093788309799350030839061814,75706164316220403423610626861470333353921225390662051210752341134842694488677)


S = int(j_E) * (X + Y)

flag = "flag{" + hashlib.md5(str(S.xy()[0]).encode()).hexdigest() + "}"
print(flag)