from hashlib import sha256
from random import randbytes

def stream_it(data, key):
    o = ''
    for b in data:
        x = sha256(key + b.encode()).hexdigest()
        o += x
    return o


KEY = b'ab' #randbytes(2)

with open("./flag.txt") as f:
    FLAG = f.read().strip()

OUT = stream_it(FLAG, KEY)

with open("./out.txt", "w") as f:
    f.write(OUT)
