from pwn import *
from Crypto.Util.number import *




"""
io = remote("groups.chal.uiuc.tf", "1337", ssl=True)



c = 1808484129731711770208540149696487911001420849891713167093938697929007759381833841136028557452772172712291524906612606708571855778522684843948194149965125927700294674036983334767691771212036104971351345829196433083603233173471350932650637581384220225201243248568980960705680860284033934261900384589561748467414571713380985583961074016711273827212383122358783056368528195542267499700660358828705469214383860206786149328147500160608932800954624458778056765233742346241
io.sendlineafter(b'c = ', str(c))

io.recvuntil(b'a = ')
a = int(io.recvline().rstrip().decode())
io.recvuntil(b'a^k = ')
h = int(io.recvline().rstrip().decode())






io.interactive()
"""

from math import gcd, log
from random import randint

def check(n, iterations=50):
    if isPrime(n):
        return False

    i = 0
    while i < iterations:
        a = randint(2, n - 1)
        if gcd(a, n) == 1:
            i += 1
            if pow(a, n - 1, n) != 1:
                return False
    return True


"""
def gen_smooth_prime(bitlen):
    # gen prime has formula 2*k + 1
    prime = [2]
    prod = 2
    while True:
        if prod.bit_length() > bitlen:
            break
        x = getPrime(30)
        prime.append(x)
        prod*=x
    x = getPrime(40)
    if not isPrime(prod * x + 1):
        x = getPrime(40)
    prime.append(x)
    prod*=x
    return math.prod(prime)+1, prime


k = 170
p, ps = gen_smooth_prime(k)

print(p, p.bit_length())
print(ps)

q, qs = gen_smooth_prime(k)

print(q, q.bit_length())
print(qs)


p, ps = gen_smooth_prime(k)

print(p, p.bit_length())
print(ps)

r, rs = gen_smooth_prime(k)

print(r, r.bit_length())
print(rs)


assert len(set(ps) & set(qs) & set(rs)) == 1
"""


"""
while True:
    num = [random.randint(1, 2**20) for _ in range(10)]
    k = math.prod(num)
    #print(k.bit_length())

    if isPrime(6*k+1) and isPrime(12*k+1) and isPrime(18*k+1):
        print("Found k", k)
        p = 6*k+1
        q = 12*k+1
        r = 18*k+1
        break



n = p*q*r

print(n, n.bit_length())

print(check(n))

print(num)
"""



"""
k = 1150186854350195032628219350277418937708281179758790630400
p = 6*k+1
q = 12*k+1
r = 18*k+1

n = p*q*r

factos_k = sorted([947563, 611519, 930028, 532213, 775008, 294140, 443514, 1017949, 112265, 347081])
print(factos_k)


g = randint(2, p-1)
x = randint(2, p-1)

y = pow(g, x, p)


print(x)
print(g)
print(y)

from sympy.ntheory import discrete_log
recv_x_modp = discrete_log(p, y, g)


print(recv_x_modp, recv_x_modp == x)



print("~"*40)

mod = p*q
print(mod.bit_length())
order = (p-1)*(q-1)

x = randint(2, mod-1)
g = randint(2, mod-1)
y = pow(g, x, mod)


print(x)
print(g)
print(y)



xp = discrete_log(p, y, g)
xq = discrete_log(q, y, g)

print(xp, xq)
print(x%(p-1), x%(q-1))

from sympy.ntheory.modular import crt
print(p)
print(q)
recv_x_modpq = crt([p-1, q-1], [xp, xq])
print(recv_x_modpq)
"""



from sage.all import *
import operator
 
first_primes = list(primes(10**7))
 
# it is important to find good lambda
# the algorithm highly depends on it
# this one is from some paper
factors = [2**5, 3**2, 5, 7, 11, 13, 17]
lam = reduce(operator.mul, factors)
# lam = /\ = 24504480
 
P = []
for p in primes(min(10000000, lam)):
    # do not include large primes so that Fermat test
    # has higher probability to pass
    if p < 400:
        continue
    if lam % p and lam % (p - 1) == 0:
        P.append(p)
 
print("P size", len(P))
 
prodlam = reduce(lambda a, b: a * b % lam, P)
prod = reduce(lambda a, b: a * b, P)
 
# faster prime checks
proof.arithmetic(False)
 
while 1:
    numlam = 1
    num = 1
    # we are building random subset {p1,...,p20}
    # and checking the subset at each step
    for i in xrange(20):
        p = choice(P)
        numlam = numlam * p % lam
        num = num * p
        if numlam != prodlam or prod % num != 0:
            continue
        q = prod // num
        print("candidate", q)
        print(factor(q))
        print()
        ps = [p for p, e in factor(q)]
        is_carm = ( (q - 1) % lcm([p-1 for p in ps]) == 0 )
        if not is_carm:
            continue
 
        # now check if q - 1 = small primes * large prime p
        # since we need to know such p
        # should happen by chance quite often
        t = q - 1
        for p in first_primes:
            while t % p == 0:
                t //= p
        if is_prime(t):
            print("Good!")
            print("q =", q, "#", len(q.bits()), "bits")
            print("p =", p, "#", len(p.bits()), "bits")
            print()
            open("candidates", "a").write("q = %d\n" % q)
            open("candidates", "a").write("p = %d\n\n" % p)









