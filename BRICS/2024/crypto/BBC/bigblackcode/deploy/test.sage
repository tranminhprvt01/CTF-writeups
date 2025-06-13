import random
import itertools
import os

def add_noise(A):
    theta_x = RR(uniform(-pi, pi))
    print(theta_x)
    Rx = matrix(RR, [[1, 0, 0], [0, cos(theta_x), -sin(theta_x)], [0, sin(theta_x), cos(theta_x)]])
    A = Rx * A

    print("~"*20)
    print(A)

    theta_y = (theta_x^2 + 2*theta_x + 2) % RR(pi)
    Ry = matrix(RR, [[cos(theta_y), 0, sin(theta_y)], [0, 1, 0], [-sin(theta_y), 0, cos(theta_y)]])
    A = A * Ry

    print("~"*20)
    print(A)

    theta_z = (theta_y^3 + 3*theta_y^2 + theta_y + 3) % RR(pi)
    Rz = matrix(RR, [[cos(theta_z), -sin(theta_z), 0], [sin(theta_z), cos(theta_z), 0], [0, 0, 1]])
    A = Rz * A
    return A


ctr = 60
secrets = [RR(uniform(-2,2)) for i in range(ctr)] # 60 entries sample uniform in [-2, 2]

ResultField = RealField(40)

perm = list(itertools.permutations(range(3), int(2)))


print(perm)

print(secrets, len(secrets))
print(ResultField)


A = random_matrix(RR, 3, 3)
idx = perm[-1]#random.choice(perm)
print(idx)
secret_index = 0
A[idx[0], idx[1]] = 100+secret_index
print(dumps(A).hex())
A[idx[0], idx[1]] = secrets[secret_index]


B = add_noise(A)
print(dumps(B).hex())

"""
we have to pass 60 test case where each test case we have:
    + random matrix A 3x3 on RR
    + after that, a random index from list perm which we known we be randomly choosen
    + A[idx[0], idx[1]] = 100 + i-th test case -> this just biefly mean in the random matrix A above, we pick a random (i, j) index and subtitute to 100 + i-th
    + but then after dumps out for us that matrix A with a noise entry inside, server re-assign that index of A into secrets[i] -> this is our goal

    + B = add_noise(A)

Considering the add noise function:

"""