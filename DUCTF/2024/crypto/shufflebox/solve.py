"""
???????????????? -> owuwspdgrtejiiud


aaaa bbbb cccc dddd 
ccac cdab dbdb bada

0123 4567 89ab cdef : index

abcd abcd abcd abcd 
bcaa dbdc dbcd acab



9, a, 0

"""


p = [9, 10, 0, 8, 11, 13, 3, 6, 15, 5, 14, 7, 4, 2, 12, 1]


def apply_perm(s):
	assert len(s) == 16
	return ''.join(s[p[i]] for i in range(16))


s1 = "aaaabbbbccccdddd"
s2 = "abcdabcdabcdabcd"


print(apply_perm(s1), "ccaccdabdbdbbada")
print(apply_perm(s2), "bcaadbdcdbcdacab")




p = [(j, i) for i, j in enumerate(p)]
print(p)
p = sorted(p)
print(p)
p = [i[1] for i in p]



c1 = "ccaccdabdbdbbada"
c2 = "bcaadbdcdbcdacab"
ct = "owuwspdgrtejiiud"

print(apply_perm(c1))

print(apply_perm(c2))

print(apply_perm(ct))


