from pwn import *
res = b'\x00'*100
with open("otp_message.txt", 'r') as f:
   for line in f: 
        inp = bytes.fromhex(line.rstrip())
        res = xor(inp, res[:len(inp)])
        print(res, len(res))