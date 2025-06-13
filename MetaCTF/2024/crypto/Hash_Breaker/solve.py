def ultrabrend(message):
    if len(message) < 29:
        message = ((message + " ") * 29)[:29]
    print(message, "xd", len(message))

    digest = [0]*32

    for i in range(len(message)):
        digest[i % 29] ^= ord(message[i])

    print(digest)

    t = digest[0] * digest[28]

    print(t, "check")

    for i in range(28):
        digest[i] = (digest[i] + digest[i+1]) % 256

    print(digest)

    digest[28] = t // 256
    digest[29] = t % 256
    digest[30] = 0xff ^ len(message)

    print(digest, "check", digest[30], digest[31])

    digest = digest[16:] + digest[:16]

    print(digest)

    for i in range(32):
        digest[i] ^= digest[(i+1) % 32] ^ i
    
    print(digest)

    return "".join(["{:02x}".format(i) for i in digest])


def reverse(message):
    digest = list(bytes.fromhex(message))
    print(digest)
    #digest = [digest[i] ^ i ^ digest[(i-1)%32] for i in range(len(digest))]
    #print(digest)


    #digest = digest[16:] + digest[:16]
    digest[14] ^= 14
    print(digest)

    for i in range(13, -1, -1):
        digest[i] ^= digest[(i+1)%32] ^ i

    print(digest)

    digest[15] ^= 15

    for i in range(16, 32):
        digest[i] ^= digest[(i-1)%32] ^ i

    digest.insert(15, 0)
    digest = digest[:-1]

    print(digest)

    digest = digest[16:] + digest[:16]

    
    print(digest)


    k = digest[30] ^ 0xff

    print(k)

    t = digest[28]*256 + digest[29]

    print(t)


    
    return -1


payload = 'Meta{' + 'abcdefghijklmnop'*2 + '}'

ct = ultrabrend(payload)
print(ct)


#ct = '1a061d36422e5a08190009ddfd34d74d603f2f7c384a08b3521c08130d171dcf'

recv = reverse(ct)
print(recv)




print("~"*40)
ct = '1a061d36422e5a08190009ddfd34d74d603f2f7c384a08b3521c08130d171dcf'

recv = reverse(ct)
print(recv)