ct = '5c4c4c6c4c3c4c3c5c4c4c6c7cbc6c3c7c3c6c8c6cfc7c5c7c4c5cfc6c3c6cfc7c5c7c4c5cfc6c3c7c4c3c0c5cfc6c3c6cdc7c9c5cfc6c3c6c2c3c0c7c9c5cfc6c3c3c4c6cec6c4c5cfc6c3c6cdc7c9c5cfc6c3c6c4c6cfc6c7c5cfc6c3c6c1c6cec6c4c5cfc6c3c6cdc7c9c5cfc6c3c6c3c3c4c3c7c7cdc0ca'


for i in range(0, len(ct), 2):
    print(bytes.fromhex(ct[:i]))

print(len(ct))
print(bytes.fromhex(ct))
