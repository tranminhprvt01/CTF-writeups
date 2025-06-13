from pwn import *


io = process(["python", "FactorGame.py"])


io.recvuntil(b'[DEBUG] p ')
p = int(io.recvline().rstrip())
io.recvuntil(b'[DEBUG] q ')
q = int(io.recvline().rstrip())

print(p)
print(q)


io.recvuntil(b'p : ')
p_ = int(io.recvline().rstrip(), 16)
io.recvuntil(b'p_mask : ')
p_mask = int(io.recvline().rstrip(), 16)

io.recvuntil(b'q : ')
q_ = int(io.recvline().rstrip(), 16)
io.recvuntil(b'q_mask : ')
q_mask = int(io.recvline().rstrip(), 16)


io.recvuntil(b'N : ')
n = int(io.recvline().rstrip(), 16)



print(n)

print(p_)
print(q_)

print(p_mask, p_mask.bit_length())
print(q_mask, q_mask.bit_length())


sol = {(0, 0)}
for i in range(max(p_mask.bit_length(), q_mask.bit_length())):
    cur_sol = set()
    for pp, qq in sol:
        for b1 in [0, 1]:
            for b2 in [0, 1]:
                p = b1*2^i + pp
                q = b2*2^i + qq
                m = 2^(i+1)
                if (p*q) % m != n % m or (p&p_mask) % m != p_ % m or (q&q_mask) % m != q_ % m:
                    continue
                cur_sol.add((p, q))
    sol = cur_sol
    print(len(sol), i)

print(sol, len(sol))
print(p%(2^p_mask.bit_length()))
print(q%(2^q_mask.bit_length()))

for p_lsb, q_lsb in sol:
    if p%(2^p_mask.bit_length()) == p_lsb:
        print("TRUE")
        bits = p_mask.bit_length()
        print(p_lsb, bits)
        P.<x> = PolynomialRing(Zmod(n))
        f = 2^bits*x + p_lsb
        f = f.monic()
        r = f.small_roots(X = 2^(512-bits), beta = 0.5, epsilon = 0.015)
        p_msb = int(r[0])
        recv_p = 2^bits*p_msb + p_lsb
        print(recv_p)
        print(p)


"""
for p_lsb, q_lsb in sol:
    print(p_lsb.bit_length())
    print(q_lsb.bit_length())
    print(p%2**p_mask.bit_length() == p_lsb)
"""


io.interactive()