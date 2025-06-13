from pwn import *

ct = open('ct', 'rb').read()
print(len(ct))

print(ct[:7] + bytes([ct[-1]]))

key = xor(ct[:7] + bytes([ct[-1]]), b'uiuctf{}')

print(key, len(key))


print(xor(key, ct))