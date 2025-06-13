from Complex import*
from Crypto.Util.number import bytes_to_long as btl, long_to_bytes as ltb, getPrime
from Crypto.Util.Padding import*
from math import*
import random
from string import *
from itertools import*
from hashlib import sha256
import time

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, cycle(b))])

def chance(primes_list):
    prime = random.choice(primes_list)
    used_primes.append(prime)
    return prime

def cute_rate(x):
    i = Complex(0, 1)
    return (i**4 + i**3 + i**2+ x)*(x*i - x**2*i**2 - i**3 + x*i**4)*chance(primes_list1)

def cute(x):
    i = Complex(0, 1)
    return (i**4 + i**3 + i**2+ x)*(x*i - x**2*i**2 - i**3 + x*i**4)

def shuffle_string(s):
    return ''.join(random.sample(s, len(s)))

def polyeval(poly, x):
    return sum([a * x**i for i, a in enumerate(poly)])

print("""            _                   _   _             
  ___ _   _| |_ ___   _ __ __ _| |_(_)_ __   __ _ 
 / __| | | | __/ _ \ | '__/ _` | __| | '_ \ / _` |
| (__| |_| | ||  __/ | | | (_| | |_| | | | | (_| |
 \___|\__,_|\__\___| |_|  \__,_|\__|_|_| |_|\__, |
                                            |___/ \n""")

input("Enter your name to rate your cute ⸜(｡˃ ᵕ < )\n")
print("Calculating your cute ... Please wait a little more (๑>؂•̀๑)\n")
time.sleep(1)

FLAG = open("./flag", 'rb').read()
words = ascii_uppercase + ascii_lowercase + digits
key = "".join([random.choice(words) for _ in range(24)])

primes_list1 = [getPrime(32) for _ in range(16)]
used_primes = []

key = shuffle_string(key).encode()
cute_fake = prod([cute_rate(u) for u in key])
cute_real = prod([cute(u) for u in key])
cute_total = cute_fake.real + cute_fake.imag

# Can you find out your real cute points?

x = int(input("Enter your lucky number \n"))
cute_total = polyeval(used_primes + [cute_total], x)

print("Total of your cute ratings: ", cute_total, "\n(˶˃⤙˂˶)")

core = sha256(str(cute_real).encode()).digest()[:16]
core_cute = xor(pad(FLAG, 16), core)

time.sleep(1)
print("Your core cute is: ", core_cute.hex(), "\n( ˶°ㅁ°) !!")
