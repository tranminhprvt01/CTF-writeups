"""
#!/usr/bin/python3

from binascii import hexlify, unhexlify

flag = hexlify(b'DEAD{test}').decode()
print(flag)

index = 0
output = ''

def FLAG_KILLER(value):
    index = 0
    temp = []
    output = 0
    while value > 0:
        temp.append(2 - (value % 4) if value % 2 != 0 else 0)
        value = (value - temp[index])/2
        index += 1
    temp = temp[::-1]
    for index in range(len(temp)):
        output += temp[index] * 3 ** (len(temp) - index - 1)
    return output


while index < len(flag):
    print(index, flag[index:index+3], int(flag[index:index+3],16), int(FLAG_KILLER(int(flag[index:index+3],16))), '%05x' % int(FLAG_KILLER(int(flag[index:index+3],16))))
    output += '%05x' % int(FLAG_KILLER(int(flag[index:index+3],16)))
    index += 3

print(output)


print(int('fff', 16))

print(int('0e98b', 16))
"""



def FLAG_KILLER(value):
    index = 0
    temp = []
    output = 0
    while value > 0:
        temp.append(2 - (value % 4) if value % 2 != 0 else 0)
        value = (value - temp[index])/2
        index += 1
    temp = temp[::-1]
    for index in range(len(temp)):
        output += temp[index] * 3 ** (len(temp) - index - 1)
    return output

dct = {int(FLAG_KILLER(i)):i for i in range(int('fff', 16)+1)}

print(dct)

ct = open("enc.txt", 'r').read()

flag = ''
ls = []

for i in range(0, len(ct), 5):
    temp = ct[i:i+5]
    flag += '%03x' % dct[int(temp, 16)]
    ls.append('%03x' % dct[int(temp, 16)])

print(flag, len(flag))
