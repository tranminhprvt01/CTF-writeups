from Crypto.Util.number import *
import requests 
from Crypto.Util.number import bytes_to_long, long_to_bytes
import time
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import binascii
import math
from Crypto.PublicKey import RSA

def ceil(a, b): return  a // b + (a % b > 0)
def floor(a,b): return  a // b

pub = RSA.import_key(open('public_key.pem', 'r').read())
n = pub.n
e = pub.e

port  = 31511

s = requests.Session()


def oracle(c):
    print(bytes_to_long(c))
    url = 'http://challenge.nahamcon.com:'+ str(port) + '/cookie'
    r   = s.get(url,cookies={
        'secret': (c).hex(),
    })
    print(r.content)
    if r.content.decode().strip() == "The secret is all good!":
        return True
    return False




def login():
    url = 'http://challenge.nahamcon.com:'+ str(port) + '/login'
    s.post(url, data={
        'username': 'admin',
        'password': 'admin'

    })
    return s.cookies['secret']


# callOracle(123)

def ceildiv(a, b):
    return -(-a // b)

def floordiv(a, b):
    return (a // b)

oracle_ctr = 0
def main():
    print('Bleichenbacher RSA padding algorithm')
    print('  for more info see 1998 paper.')
    print()

    # setup parameters, change local_setup with alternative
    # implementation, such as an oracle that uses a real server
    ct = bytes.fromhex(login())
    
    # byte length of n
    k = int(ceildiv(math.log(n,2), 8))

    # convert ciphertext from bytes into integer
    c = int.from_bytes(ct, 'big')

    # lift oracle defition to take integers
    def oracle_int(x):
        global oracle_ctr
        oracle_ctr = oracle_ctr + 1
        if oracle_ctr % 100000 == 0:
            print("[{}K tries] ".format(oracle_ctr // 1000), end='', flush=True)
        return oracle(x.to_bytes(k, 'big'))

    # define B as size of ciphertext space
    #   as first two bytes are 00 02, use 2^(keysize - 16)
    B = pow(2, 8 * (k-2))

    # precompute constants
    _2B = 2 * B
    _3B = 3 * B

    multiply = lambda x, y: (x * pow(y, e, n)) % n

    # should be identity as c is valid cipher text
    c0 = multiply(c, 1)
    assert c0 == c
    i = 1
    M = [(_2B, _3B - 1)]
    s = 1

    # ensure everything is working as expected
    if oracle_int(c0):
        print('Oracle ok, implicit step 1 passed')
    else:
        print('Oracle fail sanity check')
        exit(1)

    while True:
        if i == 1:
            print('start case 2.a: ', end='', flush=True)
            ss = ceildiv(n, _3B)
            while not oracle_int(multiply(c0, ss)):
                ss = ss + 1
            print('done. found s1 in {} iterations: {}'.format(
                ss - ceildiv(n, _3B),ss))
        else:
            assert i > 1
            if len(M) > 1:
                print('start case 2.b: ', end='', flush=True)
                ss = s + 1
                while not oracle_int(multiply(c0, ss)):
                    ss = ss + 1
                print('done. found s{} in {} iterations: {}'.format(
                    i, ss-s, ss))
            else:
                print('start case 2.c: ', end='', flush=True)
                assert len(M) == 1
                a, b = M[0]
                r = ceildiv(2 * (b * s - _2B), n)
                ctr = 0
                while True:
                    # note: the floor function below needed +1 added
                    # to it, this is not clear from the paper (see
                    # equation 2 in paper where \lt is used instead of
                    # \lte).
                    for ss in range(
                            ceildiv(_2B + r * n, b),
                            floordiv(_3B + r * n, a) + 1):
                        ctr = ctr + 1
                        if oracle_int(multiply(c0, ss)):
                            break
                    else:
                        r = r + 1
                        continue
                    break
                print('done. found s{} in {} iterations: {}'.format(i, ctr, ss))
        # step 3, narrowing solutions
        MM = []
        for a,b in M:
            for r in range(ceildiv(a * ss - _3B + 1, n),
                           floordiv(b * ss - _2B, n) + 1):
                m = (
                    max(a, ceildiv(_2B + r * n, ss)),
                    min(b, floordiv(_3B - 1 + r * n, ss))
                )
                if m not in MM:
                    MM.append(m)
                    print('found interval [{},{}]'.format(m[0],m[1]))
        # step 4, compute solutions
        M = MM
        s = ss
        i = i + 1
        if len(M) == 1 and M[0][0] == M[0][1]:
            print()
            print('Completed!')
            print('used the oracle {} times'.format(oracle_ctr))
            # note, no need to find multiplicative inverse of s0 in n
            # as s0 = 1, so M[0][0] is directly the message.
            message = M[0][0].to_bytes(k, 'big')
            print('raw decryption: {}'.format(
                binascii.hexlify(message).decode('utf-8')))
            if message[0] != 0 or message[1] != 2:
                return
            message =  message[message.index(b'\x00',1) + 1:]
            print('unpadded message hex: {}'.format(
                binascii.hexlify(message).decode('utf-8')))
            try:
                print('unpadded message ascii: {}'.format(
                    message.decode('utf-8')))
            except UnicodeError:
                pass
            return

if __name__ == "__main__":
    main()
