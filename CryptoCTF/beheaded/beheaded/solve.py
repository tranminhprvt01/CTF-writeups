
cnt = 0

ls = []

with open("all_flags.enc",'rb') as f:
    for lines in f:
        cnt+=1
        ls.append(lines.rstrip())


print(cnt)


print(len(ls[0]), len(ls[1]))



