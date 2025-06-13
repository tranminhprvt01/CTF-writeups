import os
import random
from math import prod
from Crypto.Util.number import isPrime, bytes_to_long, inverse, long_to_bytes

import time

r = random.Random(0)
def deterministicGetPrime():
  while True:
    if isPrime(p := r.getrandbits(64)):
      return p

# This is not likely to fail
assert deterministicGetPrime() == 2710959347947821323, "Your Python's random module is not compatible with this challenge."

def getPrime(bit):
  factors = [deterministicGetPrime() for _ in range(bit // 64)]
  #print(factors)
  turn=0
  while True:
    p = 2 * prod(factors) + 1
    if isPrime(p):
      print(turn)
      print(factors)
      return p
    factors.remove(random.choice(factors))
    factors.append(deterministicGetPrime())
    turn+=1


flag = os.environ.get("FLAG", "fakeflag").encode()
m = bytes_to_long(flag)

p, q = getPrime(1024), getPrime(1024)
n = p * q
e = 0x10001
c = pow(m, e, n)

print(f"{n=}")
print(f"{e=}")
print(f"{c=}")





"""

r = random.Random(0)
assert deterministicGetPrime() == 2710959347947821323

factos = [deterministicGetPrime() for _ in range(1000)]
print(factos[:10])


p_ = [factos[:16]for i in range(16)]
print(p_)
factos = factos[16:]

for _ in range(1000):
    res = []
    print(f"Sub cand {_}th", factos[_])
    for i in range(16):
        p_[i].remove(p_[i][i])
        p_[i].insert(i, factos[_])
        res.append(2*prod(p_[i])+1)
    #print(p_)
    for i in range(len(res)):
       if isPrime(res[i]):
          print(f"Found at {i}th index with {_} nums sub-ed", res[i])
          recv_p = res[i]
          print(p)
          #print(q)
          time.sleep(10)

"""


n=2350478429681099659482802009772446082018100644248516135321613920512468478639125995627622723613436514363575959981129347545346377683616601997652559989194209421585293503204692287227768734043407645110784759572198774750930099526115866644410725881688186477790001107094553659510391748347376557636648685171853839010603373478663706118665850493342775539671166315233110564897483927720435690486237018231160348429442602322737086330061842505643074752650924036094256703773247700173034557490511259257339056944624783261440335003074769966389878838392473674878449536592166047002406250295311924149998650337286245273761909
e=65537
c=945455686374900611982512983855180418093086799652768743864445887891673833536194784436479986018226808021869459762652060495495939514186099959619150594580806928854502608487090614914226527710432592362185466014910082946747720345943963459584430804168801787831721882743415735573097846726969566369857274720210999142004037914646773788750511310948953348263288281876918925575402242949315439533982980005949680451780931608479641161670505447003036276496409290185385863265908516453044673078999800497412772426465138742141279302235558029258772175141248590241406152365769987248447302410223052788101550323890531305166459



r = random.Random(0)
assert deterministicGetPrime() == 2710959347947821323

factos = [deterministicGetPrime() for _ in range(1000)]



from gmpy2 import mpz, powmod, next_prime, gcd

def polard(n: int, factos):
    g = mpz(3)
    factos = sorted(factos)
    cur = factos[0]
    # pbar = tqdm(total=int(cap))
    # pbar.update(int(cur))
    while cur < factos[-1]:
        g = powmod(g, cur**10, n)
        if g == 1:
            break
        check = gcd(g - 1, n)
        if check != 1:
            return int(check)
        factos = factos[1:]
        nx = factos[0]
        # delta = nx - cur
        # pbar.update(int(delta))
        cur = nx
        # pbar.close()
    return None


p = polard(n, factos)


q = n//p
d = inverse(e, (p-1)*(q-1))


print(long_to_bytes(pow(c, d, n)))





