import numpy as np
import time
from Crypto.Util.number import *

# get e
import requests
reply = requests.get('https://apod.nasa.gov/htmltest/gifcity/e.2mil').text
e = ''.join([line for line in [line.strip() for line in reply.split('\n')] if line and line.strip()[0].isdigit()])

tick = time.time()

    
i = 0
se = e.replace('.','')
primes = []
while True:
    if len(primes) == 1000:
        f = open("primes.txt", 'w')
        f.write(str(primes))
        f.close()
        break
    frag = se[i:i+154]
    if isPrime(int(frag)):
        #print(frag)
        primes.append(int(frag))
    i+= 1

check = 7728751393377105569802455757436190501772466214587592374418657530064998056688376964229825501195065837843125232135309371235243969149662310110328243570065781

print(check in primes)