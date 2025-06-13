import random

class PRNG:
    def __init__(self):
        self.b = 128
        self.r = 64
        self.M = 2**self.b
        self.m = 2**self.r
        self.MULT = random.randint(0, self.M)
        self.INC = 0 
        self.SEED = random.randint(0, self.M)

    def getval(self):
        print(self.SEED)
        print(self.SEED - self.SEED % 2**self.r, self.SEED - self.SEED % self.m)
        return (self.SEED - self.SEED % 2**self.r, self.MULT, self.M)

    def next(self):
        self.SEED = ((self.SEED * self.MULT) + self.INC) % self.M
        return self.SEED



prng = PRNG()

print(prng.getval())
prng.next()
print(prng.getval())