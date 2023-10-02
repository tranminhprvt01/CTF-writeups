from pwn import *

c1 = open("c1", 'rb').read()
c2 = open("c2", 'rb').read()
c3 = open("c3", 'rb').read()
p2 = open("p2", 'rb').read()

key = xor(c2, p2)

print(key)

m1 = xor(key, c1)
m3 = xor(key, c3)

print(m1)
print(m3)


