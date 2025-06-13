from pwn import *
from Crypto.Util.number import *

#io = process(["python3", "main.py"])
io = remote("34.42.147.172", "8007")

io.recvuntil(b"To prove that the scheme works, i'll test it with a sample message.\n")
enc = eval(io.recvline().rstrip().decode())

print(len(enc))



class testhash:
    def __init__(self, data):
        self.data = data

    def digest(self):
        return self.data 


hashes = []
hashes.append(testhash) 
hashes.append(hashlib.md5)
hashes.append(hashlib.sha224)
hashes.append(hashlib.sha256)
hashes.append(hashlib.sha3_224)
hashes.append(hashlib.sha3_256)


h = [bytes_to_long(i(b'a').digest()) for i in hashes]


print(h)


io.sendlineafter(b'Enter your choice: ', b'1')
io.sendlineafter(b'Please enter the message to be signed: ', b'a')
c1 = eval(io.recvline().rstrip().decode())
f1 = c1[-1]
c1 = c1[:-1]
rhs1 = sum([i*j for i, j in zip(h, c1)])




io.sendlineafter(b'Enter your choice: ', b'1')
io.sendlineafter(b'Please enter the message to be signed: ', b'a')
c2 = eval(io.recvline().rstrip().decode())
f2 = c2[-1]
c2 = c2[:-1]
rhs2 = sum([i*j for i, j in zip(h, c2)])



kp = GCD(rhs1 - f1, rhs2 - f2)

print(kp)

if not isPrime(kp):
    factos = list(factor(kp, 2^10))
    print(factos)
    p = factos[-1][0]
else:
    p = kp





C = enc[-1]
enc = enc[:-1]


A = matrix([[enc[i] for i in range(len(enc))] + [-C, p]])

print(A.parent())
print(A)

A=A.stack(identity_matrix(8))

print(A.parent())

A = A.transpose()
A = A.LLL()

for rows in A:
    print(rows)
    if rows[0] == 0:
        print(long_to_bytes(int(abs(rows[1]))))
        break































io.interactive()