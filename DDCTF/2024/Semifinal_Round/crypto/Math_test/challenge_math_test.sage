from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import hashlib
import random

p = getPrime(256)

A = random.randint(0, 2**256)
B = random.randint(0, 2**256)

E = EllipticCurve(GF(p), [A, B])

X = E.random_element()
Y = E.random_element()

print(f"{X=}") # X=(70531110072509298803201621415592601393387767551616451246154013182556851771153 : 3128592393207593101775747511252725036748347188549955655359151644135290113924 : 1)
print(f"{Y=}") # Y=(58557423359848065299975326112549968009731308453890093788309799350030839061814 : 75706164316220403423610626861470333353921225390662051210752341134842694488677 : 1)
print(f"{p=}") # p=91725037968177304595356229847249124275634668177296814741529573801095034173523

# Find A, B
# A = ...
# B = ...

# Compute J-invariant
# j_E = ...

# Computing Secret
S = int(j_E) * (X + Y)
flag = "flag{" + hashlib.md5(str(S.xy()[0]).encode()).hexdigest() + "}"
print(flag)