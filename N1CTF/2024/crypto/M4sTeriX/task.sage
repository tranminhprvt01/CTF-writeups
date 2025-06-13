from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from hashlib import md5
from random import *

FLAG = b"n1ctf{REDACTED}"
N, n, q = 1024, 60, 2**521-1
F, Fq = Zmod(256), GF(q)
s = [random_vector(F, N//2) for _ in range(20)]

def error_work(s, w):
    a = random_matrix(F, N//2, N); mat.append(a)
    e = list(random_vector(w, x=1, y=256))+[0]*(N-w)
    P = Permutations(N).random_element().to_matrix()
    return matrix(Fq, 4, N//4, s*a+P*vector(e))

def tedious_work(A):
    α = random_matrix(Fq, n, N//4)
    ε = matrix(n, N//4, [i*randrange(0, q) for i in α])
    σ = matrix(Fq, [[randrange(1, q) for i in range(80)] for j in range(n)])
    open("tedious", "w").write(str({"π": list(σ*A+ε), "α": list(α)}))


mat = []
A = matrix(Fq, 80, N//4)
for i in range(20):
    A[4*i:4*i+4,:] = error_work(s[i], 22)

save(mat, "mat")
tedious_work(A)
cipher = AES.new(md5(str(sum(s)).encode()).digest(), AES.MODE_ECB)
print(cipher.encrypt(pad(FLAG, 16)).hex())
"""
af3010a3de0fa968c38f421f2857d6c60caf9a6ae1023e9d04f253e1d5fb8038fddf26f7cc976fadbb2df12ef549d1fd
"""