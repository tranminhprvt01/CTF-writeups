
flag = ''
a = [0]


for i in range(355):
    b = [_+1 for _ in a]
    c = [_+1 for _ in b]
    a += b + c


    # print(b)
    # print(c)
    # print(a)
    # print("~"*40)


print(len(a))