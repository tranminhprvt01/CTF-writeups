from Crypto.Util.number import *
import math

b = 0x9F939C02A7BD7FC263A4CCE416F4C575F28D0C1315C4F0C282FCA6709A5F9F7F9C251C9EEDE9EB1BAA31602167FA5380
a = 0xA079DB08EA2470350C182487B50F7707DD46A58A1D160FF79297DCC9BFAD6CFC96A81C4A97564118A40331FE0FC1327F
p = 0xC90102FAA48F18B5EAC1F76BB40A1B9FB0D841712BBE3E5576A7A56976C2BAECA47809765283AA078583E1E65172A3FD

E = EllipticCurve(GF(p), [a, b])

print(E)

print(E.order())


Gx = 0x087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8
Gy = 0x127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182

G = E(Gx, Gy)

print(G)
print(G.order())

Qax = 0x195b46a760ed5a425dadcab37945867056d3e1a50124fffab78651193cea7758d4d590bed4f5f62d4a291270f1dcf499
Qay = 0x357731edebf0745d081033a668b58aaa51fa0b4fc02cd64c7e8668a016f0ec1317fcac24d8ec9f3e75167077561e2a15

Qbx = 0xb3e5f89f04d49834de312110ae05f0649b3f0bbe2987304fc4ec2f46d6f036f1a897807c4e693e0bb5cd9ac8a8005f06
Qby = 0x85944d98396918741316cd0109929cb706af0cca1eaf378219c5286bdc21e979210390573e3047645e1969bdbcb667eb


Qa = E(Qax, Qay)
Qb = E(Qbx, Qby)

print(Qa)
print(Qb)

factos = [i[0] for i in list(factor(G.order()))]
print(factos)

dlogs = []
mod = []
for fac in factos:
    if int(fac).bit_length() > 200:
        break
    t = int(G.order()) // int(fac)
    dlog = discrete_log(t*Qa, t*G, G.order(), operation="+")
    dlogs += [dlog]
    mod += [fac]

    #print(dlogs)
    
    
print(crt(dlogs, mod))

k = crt(dlogs, mod)

subgr_ord = math.prod(mod)
print(subgr_ord)



"""
from tqdm import tqdm
for i in tqdm(range(10**6)):
    d = int(k) + i*subgr_ord
    if d*G == Qa:
        print("Recover secret", d)
        break
"""


d = 168606034648973740214207039875253762473

share = d*Qb
print(share)
print(share.xy()[0])



