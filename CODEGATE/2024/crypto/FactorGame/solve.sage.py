

# This file was *autogenerated* from the file solve.sage
from sage.all_cmdline import *   # import sage library

_sage_const_16 = Integer(16); _sage_const_0 = Integer(0); _sage_const_1 = Integer(1); _sage_const_2 = Integer(2); _sage_const_512 = Integer(512); _sage_const_0p5 = RealNumber('0.5'); _sage_const_0p015 = RealNumber('0.015')
from pwn import *


io = process(["python", "FactorGame.py"])


io.recvuntil(b'[DEBUG] p ')
p = int(io.recvline().rstrip())
io.recvuntil(b'[DEBUG] q ')
q = int(io.recvline().rstrip())

print(p)
print(q)


io.recvuntil(b'p : ')
p_ = int(io.recvline().rstrip(), _sage_const_16 )
io.recvuntil(b'p_mask : ')
p_mask = int(io.recvline().rstrip(), _sage_const_16 )

io.recvuntil(b'q : ')
q_ = int(io.recvline().rstrip(), _sage_const_16 )
io.recvuntil(b'q_mask : ')
q_mask = int(io.recvline().rstrip(), _sage_const_16 )


io.recvuntil(b'N : ')
n = int(io.recvline().rstrip(), _sage_const_16 )



print(n)

print(p_)
print(q_)

print(p_mask, p_mask.bit_length())
print(q_mask, q_mask.bit_length())


sol = {(_sage_const_0 , _sage_const_0 )}
for i in range(max(p_mask.bit_length(), q_mask.bit_length())):
    cur_sol = set()
    for pp, qq in sol:
        for b1 in [_sage_const_0 , _sage_const_1 ]:
            for b2 in [_sage_const_0 , _sage_const_1 ]:
                p = b1*_sage_const_2 **i + pp
                q = b2*_sage_const_2 **i + qq
                m = _sage_const_2 **(i+_sage_const_1 )
                if (p*q) % m != n % m or (p&p_mask) % m != p_ % m or (q&q_mask) % m != q_ % m:
                    continue
                cur_sol.add((p, q))
    sol = cur_sol
    print(len(sol), i)

print(sol, len(sol))
print(p%(_sage_const_2 **p_mask.bit_length()))
print(q%(_sage_const_2 **q_mask.bit_length()))

for p_lsb, q_lsb in sol:
    if p%(_sage_const_2 **p_mask.bit_length()) == p_lsb:
        print("TRUE")
        bits = p_mask.bit_length()
        print(p_lsb, bits)
        P = PolynomialRing(Zmod(n), names=('x',)); (x,) = P._first_ngens(1)
        f = _sage_const_2 **bits*x + p_lsb
        f = f.monic()
        r = f.small_roots(X = _sage_const_2 **(_sage_const_512 -bits), beta = _sage_const_0p5 , epsilon = _sage_const_0p015 )
        p_msb = int(r[_sage_const_0 ])
        recv_p = _sage_const_2 **bits*p_msb + p_lsb
        print(recv_p)
        print(p)


"""
for p_lsb, q_lsb in sol:
    print(p_lsb.bit_length())
    print(q_lsb.bit_length())
    print(p%2**p_mask.bit_length() == p_lsb)
"""


io.interactive()

