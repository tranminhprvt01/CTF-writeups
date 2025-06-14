

# This file was *autogenerated* from the file solve.sage
from sage.all_cmdline import *   # import sage library

_sage_const_2 = Integer(2); _sage_const_1 = Integer(1); _sage_const_13547455976491887509 = Integer(13547455976491887509); _sage_const_1718638078090105081 = Integer(1718638078090105081); _sage_const_23 = Integer(23); _sage_const_12730023331974797949 = Integer(12730023331974797949); _sage_const_0 = Integer(0); _sage_const_37 = Integer(37); _sage_const_20 = Integer(20); _sage_const_25 = Integer(25); _sage_const_10 = Integer(10); _sage_const_10000 = Integer(10000)# assert __import__('re').fullmatch(r'SEE{\w{23}}',flag:=input()) and not int.from_bytes(flag.encode(),'big')%13**37

import string
import re

chrs = string.ascii_lowercase.encode()
avg = sorted(chrs)[len(chrs) // _sage_const_2 ] - _sage_const_1 
print(f"{avg = }")
print([x - avg for x in sorted(chrs)])  # within [-37, 37]

M = _sage_const_13547455976491887509 
C = _sage_const_1718638078090105081 #int.from_bytes(b"SEE{" + b"\x00" * 23 + b"}", "big")

P = PolynomialRing(ZZ, "ap", _sage_const_23 )
aps = P.gens()
aa = [ap + avg for ap in aps]
f = C + sum([a * _sage_const_12730023331974797949 **i for i, a in enumerate(aa)]) * _sage_const_12730023331974797949 
print(f)

L = matrix(f.coefficients()).T
L = block_matrix([[M, _sage_const_0 ], [L, _sage_const_1 ]])
bounds = [_sage_const_1 ] + [_sage_const_37 ] * _sage_const_23  + [_sage_const_1 ]
scale = [_sage_const_2 **_sage_const_20  // i for i in bounds]
Q = diagonal_matrix(scale)
L *= Q
L = L.BKZ(block_size=_sage_const_25 )
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

L[:, _sage_const_0 ] *= _sage_const_2 **_sage_const_10 
A = IntegerMatrix.from_matrix(L.change_ring(ZZ))
LLL.reduction(A)
MG = MatGSO(A)
MG.update_gso()
sol_cnt = _sage_const_10000 
enum = Enumeration(MG, sol_cnt)
size = int(L.nrows())
bound = _sage_const_37 
answers = enum.enumerate(_sage_const_0 , size, (size * bound**_sage_const_2 ), _sage_const_0 , pruning=None)
for _, s in answers:
    v = IntegerMatrix.from_iterable(_sage_const_1 , A.nrows, map(int, s))
    sv = v * A

    if abs(sv[_sage_const_0 , size - _sage_const_1 ]) <= bound and sv[_sage_const_0 , -_sage_const_1 ] in (-_sage_const_1 , _sage_const_1 ):
        print(sv)
        neg = sv[_sage_const_0 , -_sage_const_1 ]
        sol = [neg * sv[_sage_const_0 , i + _sage_const_1 ] for i in range(_sage_const_23 )]
        assert f(*sol) % M == _sage_const_0 
        aa = [x + avg for x in sol][::-_sage_const_1 ]
        flag = bytes(aa)
        #assert int.from_bytes(flag, "big") % M == 0
        print(flag)
        
# SEE{luQ5xmNUKgEEDO_c5LoJCum}

