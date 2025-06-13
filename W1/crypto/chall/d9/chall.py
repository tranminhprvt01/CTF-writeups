import collections
import random
import os 
from secret import FLAG
from hashlib import sha256 
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl 
def inv(n, q):
    return egcd(n, q)[0] % q


def egcd(a, b):
    s0, s1, t0, t1 = 1, 0, 0, 1
    while b > 0:
        q, r = divmod(a, b)
        a, b = b, r
        s0, s1, t0, t1 = s1, s0 - q * s1, t1, t0 - q * t1
        pass
    return s0, t0, a


def sqrt(n, q):
    assert n < q
    for i in range(1, q):
        if i * i % q == n:
            return (i, q - i)
        pass
    raise Exception("not found")

################### ECC Implement ###################

Coord = collections.namedtuple("Coord", ["x", "y"])


class EC(object):
    """System of Elliptic Curve"""
    def __init__(self, a, b, q, n):
        """elliptic curve as: (y**2 = x**3 + a * x + b) mod q
        - a, b: params of curve formula
        - q: prime number
        """
        assert 0 < a and a < q and 0 < b and b < q and q > 2
        assert (4 * (a ** 3) + 27 * (b ** 2))  % q != 0
        self.a = a
        self.b = b
        self.q = q
        self.zero = Coord(0, 0)
        self.order = n
        pass

    def is_valid(self, p):
        if p == self.zero: return True
        l = (p.y ** 2) % self.q
        r = ((p.x ** 3) + self.a * p.x + self.b) % self.q
        return l == r

    def at(self, x):
        assert x < self.q
        ysq = (x ** 3 + self.a * x + self.b) % self.q
        y, my = sqrt(ysq, self.q)
        return Coord(x, y), Coord(x, my)

    def neg(self, p):
        return Coord(p.x, -p.y % self.q)

    def add(self, p1, p2):
        if p1 == self.zero: return p2
        if p2 == self.zero: return p1
        if p1.x == p2.x and (p1.y != p2.y or p1.y == 0):
            return self.zero
        if p1.x == p2.x:
            l = (3 * p1.x * p1.x + self.a) * inv(2 * p1.y, self.q) % self.q
            pass
        else:
            l = (p2.y - p1.y) * inv(p2.x - p1.x, self.q) % self.q
            pass
        x = (l * l - p1.x - p2.x) % self.q
        y = (l * (p1.x - x) - p1.y) % self.q
        return Coord(x, y)

    def mul(self, p, n):
        r = self.zero
        m2 = p
        while 0 < n:
            if n & 1 == 1:
                r = self.add(r, m2)
                pass
            n, m2 = n >> 1, self.add(m2, m2)
            pass
        return r

    # def order(self, g):
    #     assert self.is_valid(g) and g != self.zero
    #     for i in range(1, self.q + 1):
    #         if self.mul(g, i) == self.zero:
    #             return i
    #         pass
    #     raise Exception("Invalid order")
    # pass

class DSA(object):
    def __init__(self, ec : EC, g : Coord):
        self.ec = ec
        self.g = g
        self.n = ec.order
        pass

    def gen(self, priv):
        assert 0 < priv and priv < self.n
        return self.ec.mul(self.g, priv)

    def sign(self, hashval, priv, r):
        assert 0 < r and r < self.n
        m = self.ec.mul(self.g, r)
        return (m.x, inv(r, self.n) * (hashval + m.x * priv) % self.n)
 
    def validate(self, hashval, sig, pub):
        assert self.ec.is_valid(pub)
        assert self.ec.mul(pub, self.n) == self.ec.zero
        w = inv(sig[1], self.n)
        u1, u2 = hashval * w % self.n, sig[0] * w % self.n
        p = self.ec.add(self.ec.mul(self.g, u1), self.ec.mul(pub, u2))
        return p.x % self.n == sig[0]
    pass

################### End of ECC Implement ###################

def get_random_bytes(num):
    return os.urandom(num) + random.randbytes(num)

import json


######### redo this after done code
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
curve_order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = Coord(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, \
          0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
ec_object = EC(A, B, P, curve_order)
dsa_object = DSA(ec_object, G)


Ln = 256
while True:
    privkey = int.from_bytes(get_random_bytes((curve_order).bit_length() //16), "big")
    if privkey < curve_order:
        break
pubkey = ec_object.mul(G, privkey)
current_user = None

###################################


 
def register_account(username : str, isAdmin : bool):
    tmp = {"username" : username, "isAdmin" : isAdmin}

    user_id = get_random_bytes(8)
    tmp["userID"] = user_id.hex()

    while True:
        random_k = int.from_bytes(get_random_bytes((curve_order).bit_length() //16), "big")
        if random_k < curve_order:
            break
    tmp_hash = btl(sha256(json.dumps(tmp).encode()).digest()[:Ln])
    r, s = dsa_object.sign(tmp_hash, privkey, random_k)

    cookie = ltb(r).hex() + "." + ltb(s).hex()
    return tmp, cookie

def register():
    username = input("Enter your username: ").strip()
    account_info, cookie = register_account(username, False)
    print("Account information:")
    print(json.dumps(account_info))
    print("Cookie:", cookie)

def login_account(jsonstr : str, cookie : str):
    global current_user
    try:
        # print(jsonstr.encode())
        jsonobject = json.loads(jsonstr)
    except:
        raise Exception("Cannot deserialize json object!")

    for i in jsonobject:
        if i == "username" or i == "isAdmin"  or i == "userID":
            continue
        else:
            raise Exception(f"Keyword not permit in json object: {i}")
    for i in ["username", "isAdmin", "userID"]:
        if not (i in jsonobject):
            raise Exception("Wrong object format!")
    try:
        r, s = cookie.split(".")
        r = btl(bytes.fromhex(r))
        s = btl(bytes.fromhex(s))
    except:
        raise Exception("Wrong cookie format!")

    jsonstr_hash = btl(sha256(jsonstr.encode()).digest()[:Ln])
    if (dsa_object.validate(jsonstr_hash, (r, s), pubkey)):
        current_user = jsonobject
        print("Login sucessfully!")
    else:
        raise Exception("Invalid cookie!")

def login():
    jsonstr = input("Enter your account information: ").strip().replace("\n", "")
    cookie = input("Your cookie: ").strip().replace("\n", "")
    try:
        login_account(jsonstr, cookie)
    except Exception as e:
        print(e)
    

def print_flag():
    global current_user
    if current_user == None:
        print("You have not login yet!")
        return
    elif not current_user["isAdmin"]:
        print("Your dont have permission to view secret!")
        return
    else:
        print(f"Flag is: {FLAG.decode()}")


def gaccha():
    global current_user 
    if current_user == None:
        print("You have not login yet!")
        return
    yourNumber = int(input("Enter your lucky number: "))
    print("Please wait while we get the result!")
    winningNumber = int.from_bytes(get_random_bytes(3), "big")
    print(f"Your number is: {yourNumber}")
    print(f"Lucky number is: {winningNumber}")
    if (winningNumber == yourNumber):
        print("congratz, you have just won the flag.")
        print(f"Flag is: {FLAG.decode()}")
    else:
        print("Better luck next time!")



def menu():
    print("1. Login")
    print("2. Register")
    print("3. Get flag")
    print("4. Gaccha")
    print("5. Exit")




def challenge():
    while True:
        menu()
        cmd = int(input(">> "))
        if cmd == 1:
            login()
        elif cmd == 2:
            register()
        elif cmd == 3:
            print_flag()
        elif cmd == 4:
            gaccha()
        elif cmd == 5:
            exit(0)
        else:
            print("Invalid command")


challenge()