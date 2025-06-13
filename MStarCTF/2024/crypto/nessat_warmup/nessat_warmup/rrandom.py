from os import urandom
from typing import Any

m = 2 ** 255 + 95


class LCG:
    def __init__(self, seed):
        self.a = 21
        self.b = 7
        self.m = m
        self.state = seed % self.m

    def get(self):
        self.state = (self.a * self.state + self.b) % self.m
        return self.state


lcg = LCG(int.from_bytes(urandom(16)))


def randbelow(n: int) -> int:
    if n > m:
        raise ValueError("So big values are not supported")
    return lcg.get() % n


def randint(lower: int, upper: int) -> int:
    if upper < lower:
        raise ValueError("Bad call")
    return lower + randbelow(upper - lower)


def choices(arr: list[Any], k=-1):
    if k == -1:
        raise ValueError("You should specify k")
    res = []
    for i in range(k):
        index = randint(0, len(arr))
        res.append(arr[index])
    return res
