import subprocess

secret = open('secret.txt').read().strip()
secretbits = ''.join(f'{ord(i):08b}' for i in secret)

print(len(secretbits))
print(secretbits[:8])

output = []
output1 = []
for bit in secretbits:
    if bit == '0':
        output += [float(i) for i in subprocess.check_output('./d8 gen.js', shell=True).decode().split()]
        #output1 += [float(i) for i in subprocess.check_output('node gen.js', shell=True).decode().split()]
    else:
        output += [float(i) for i in subprocess.check_output('node gen.js', shell=True).decode().split()]
        #output1 += [float(i) for i in subprocess.check_output('./d8 gen.js', shell=True).decode().split()]


print(len(output))

print(output[:24])

print("~"*20)
print(output[24:48])

print("~"*20)
print(output[48:72])
print("~"*20)
print(output[72:96])