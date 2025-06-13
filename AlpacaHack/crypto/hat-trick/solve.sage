# assert __import__('re').fullmatch(r'SEE{\w{23}}',flag:=input()) and not int.from_bytes(flag.encode(),'big')%13**37

import string
import re

chrs = string.ascii_lowercase.encode()
avg = sorted(chrs)[len(chrs) // 2] - 1
print(f"{avg = }")
print([x - avg for x in sorted(chrs)])  # within [-37, 37]

M = 13547455976491887509
C = 1718638078090105081#int.from_bytes(b"SEE{" + b"\x00" * 23 + b"}", "big")

P = PolynomialRing(ZZ, "ap", 23)
aps = P.gens()
aa = [ap + avg for ap in aps]
f = C + sum([a * 12730023331974797949**i for i, a in enumerate(aa)]) * 12730023331974797949
print(f)

L = matrix(f.coefficients()).T
L = block_matrix([[M, 0], [L, 1]])
bounds = [1] + [37] * 23 + [1]
scale = [2**20 // i for i in bounds]
Q = diagonal_matrix(scale)
L *= Q
L = L.BKZ(block_size=25)
L /= Q

# not good enough
# for row in L:
#     if row[-1] < 0:
#         row = -row
#     if row[0] == 0 and row[-1] == 1:
#         print(row)
#         print(f(*row[1:-1]) % M == 0)
#         aa = [x + avg for x in row[1:-1]][::-1]
#         flag = b"SEE{" + bytes(aa) + b"}"
#         assert int.from_bytes(flag, "big") % M == 0
#         print(flag)
# exit()

# lattice enumeration code copied from https://project-euphoria.dev/blog/37-not-new-prng/
from fpylll import IntegerMatrix, LLL
from fpylll.fplll.gso import MatGSO
from fpylll.fplll.enumeration import Enumeration

sols = []

L[:, 0] *= 2**10
A = IntegerMatrix.from_matrix(L.change_ring(ZZ))
LLL.reduction(A)
MG = MatGSO(A)
MG.update_gso()
sol_cnt = 10000
enum = Enumeration(MG, sol_cnt)
size = int(L.nrows())
bound = 37
answers = enum.enumerate(0, size, (size * bound**2), 0, pruning=None)
for _, s in answers:
    v = IntegerMatrix.from_iterable(1, A.nrows, map(int, s))
    sv = v * A

    if abs(sv[0, size - 1]) <= bound and sv[0, -1] in (-1, 1):
        print(sv)
        neg = sv[0, -1]
        sol = [neg * sv[0, i + 1] for i in range(23)]
        assert f(*sol) % M == 0
        aa = [x + avg for x in sol][::-1]
        flag = bytes(aa)
        #assert int.from_bytes(flag, "big") % M == 0
        print(flag)
        
# SEE{luQ5xmNUKgEEDO_c5LoJCum}
