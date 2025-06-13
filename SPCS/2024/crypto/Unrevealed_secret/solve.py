def xor_cipher(message, key):
    # This function performs XOR encryption on the message and key
    message_nums = [ord(c) for c in message]
    key_nums = [ord(c) for c in key]
    cipher_nums = [m ^ k for m, k in zip(message_nums, key_nums)]
    return ''.join(chr(i) for i in cipher_nums)

ct = open("encrypted_flag.txt", 'r', encoding='utf-8').read()


print(ct, len(ct))

known = 'grodno{'

key = xor_cipher(known, ct[:len(known)])
print(key, len(key))
while len(key) < len(ct):
    key += key[-1]


print(key, len(key))

print(xor_cipher(key, ct))



