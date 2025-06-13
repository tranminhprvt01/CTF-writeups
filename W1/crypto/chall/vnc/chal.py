from functools import reduce
from random import getrandbits, randint
from hashlib import sha256

import sys
sys.setrecursionlimit(10**8)
sys.set_int_max_str_digits(10**8)

N_BITS   = 128
N_ROUNDS = 10
FLAG     = "W1{test_flag}"

class OLA:
    @classmethod
    def sussuffle(cls, arr: list, key: list, times: int) -> list:
        assert len(arr) == len(key) == N_BITS and times > 0
        def sus(*fn_s):
            return reduce(lambda x,y:(lambda z,t: x(y(z,t),t)), fn_s)
        
        fn = lambda vars_1,vars_2: [reduce(lambda x,y:(x^y), [z&t for z,t in zip(vars_1,vars_2)])]+vars_1[:-1]
        return sus(*[fn]*times)(arr,key)

    @classmethod
    def encrypt(cls, msg: int, key1: list, key2: list):
        msg = list(map(int, bin(msg)[2:].zfill(N_BITS)))
        assert len(msg) == len(key1) == len(key2) == N_BITS
        
        res = []
        for b in msg:
            nonce   = list(map(int, bin(getrandbits(N_BITS))[2:].zfill(N_BITS)))
            counter = randint(13,37) # ok that enough!
            if b:
                tmp = cls.sussuffle(nonce, key1, counter)
            else:
                tmp = cls.sussuffle(nonce, key2, counter)
            res.append("".join(list(map(str, tmp))))
        return int("".join(res), 2)
    
    @classmethod
    def decrypt(cls, enc: int, key1: list, key2: list):
        # TODO :<
        pass

class Challenge:
    def __init__(self, N) -> None:
        self.cur_rounds = 0
        self.MAX_ROUNDS = N
    
    def new_challenge(self):
        self.key1 = list(map(int, bin(getrandbits(N_BITS-1))[2:].zfill(N_BITS-1)))+[0] # make surve key1 != key2 :>
        self.key2 = list(map(int, bin(getrandbits(N_BITS-1))[2:].zfill(N_BITS-1)))+[1] # make surve key1 != key2 :>
        self.secret      = getrandbits(N_BITS)
        self.cur_rounds += 1

    def run_challenge(self):
        for _ in range(self.MAX_ROUNDS):
            self.do_round()
        print("bro won :> Flag:", FLAG)

    def do_round(self):
        self.new_challenge()
        print("[+] Round %02d/%02d: Find `s` that sha256(`s`)=%s" 
            % (self.cur_rounds, self.MAX_ROUNDS, sha256(str(self.secret).encode()).hexdigest()))

        while True:
            opt = int(input("opt: "))
            if opt == 1:
                print(OLA.encrypt(self.secret, self.key1, self.key2))
            elif opt == 2:
                guess = int(input("secret: "))
                if self.secret != guess:
                    print("bro failed :<")
                    exit(1)
                break
            elif opt == 1337:
                print("bye bro :>")
                exit(1)
            else:
                print("wtf bro :<")

if __name__ == "__main__":
    Challenge(N_ROUNDS).run_challenge()