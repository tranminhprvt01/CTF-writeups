import random
random.seed(1337)

ops = [
    lambda x: x+3,
    lambda x: x-3,
    lambda x: x*3,
    lambda x: x^3,
]


de_ops = [
    lambda x: x-3,
    lambda x: x+3,
    lambda x: x//3,
    lambda x: x^3,
]

ct = [354, 112, 297, 119, 306, 369, 111, 108, 333, 110, 112, 92, 111, 315, 104, 102, 285, 102, 303, 100, 112, 94, 111, 285, 97, 351, 113, 98, 108, 118, 109, 119, 98, 94, 51, 56, 159, 50, 53, 153, 100, 144, 98, 51, 53, 303, 99, 52, 49, 128]


flag = [random.choice(de_ops)(i) for i in ct]


print(flag)
print(bytes(flag))


