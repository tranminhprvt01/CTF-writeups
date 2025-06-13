

s = "5B 6E 73 5A 73 6E 7B 6A 77 78 6E 79 7E 25 0F 4A 51 4A 37 35 38 35 25 48 74 7A 77 78 6A 0F 5C 6A 71 68 74 72 6A 26 26 26"

ls_num = list(bytes.fromhex(s))

print(ls_num)

ls_num = [i-5 for i in ls_num]

print(ls_num)

print(bytes(ls_num))
print(bytes(ls_num).decode())
