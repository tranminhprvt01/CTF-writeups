from Crypto.Util.number import long_to_bytes, bytes_to_long

#ch1 and ch2 are strings of 0s and 1s
def different_bits1(ch1,ch2):
    count = 0
    for i in range(len(ch1)):
        if ch1[i] != ch2[i]:
            count += 1
    return count
#both functions do the same thing but what is that ^ sign? you should search it
def different_bits2(ch1,ch2):
    count = 0
    xor = int(ch1,2) ^ int(ch2,2)
    while xor:
        count += xor & 1
        xor >>= 1
    return count

#FLAG=Securinets{flag_content}
#assert different_bits1(ch1,ch2)==9

different_bits_indexes=[a,b,c,d,e,f,g,h,i]
#a,b,c,d,e,f,g,h,i are indexes of different bits in the bit strings, they are numbers
for i in different_bits_indexes:
    assert i%15==4

flag_content="###########"
ascb=bytes_to_long(flag_content.encode())
ch1=bin(ascb)[2:]
ch2=""
for i in range(len(ch1)):
    if i%15!=4:
        ch2+=ch1[i]
    else:
        ch2+=str(int(ch1[i])^1)

print(ch2)
print(long_to_bytes(int(ch2,2)))
