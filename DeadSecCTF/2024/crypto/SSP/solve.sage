from pwn import *

from itertools import combinations
from tqdm import tqdm
from Crypto.Util.number import *

def solve_subset(arr_, s, brute):
    for arr in tqdm(combinations(arr_, len(arr_) - brute)):
        N = ceil(sqrt(len(arr)) / 2)
        M = identity_matrix(QQ, len(arr))
        M = M.augment(N*vector(arr))
        M = M.stack(vector([-1/2 for _ in range(len(arr))] + [-N*s]))

        for row in M.LLL():
            for row in (row, -row):
                kk = [i+1/2 for i in row][:-1]
                if not all([i in (0, 1) for i in kk]):
                    continue
                subset = [xx for xx, k in zip(arr, kk) if k]
                if sum(subset) == s:
                    return subset


def is_subset_sum(set, target):
    n = len(set)
    subset = [False] * n

    def backtrack(index, current_sum):
        if current_sum == target:
            return True
        if current_sum > target or index == n:
            return False

        # Include the current element in the subset
        subset[index] = True
        if backtrack(index + 1, current_sum + set[index]):
            return True

        # Exclude the current element from the subset
        subset[index] = False
        if backtrack(index + 1, current_sum):
            return True

        return False

    if backtrack(0, 0):
        # Subset with the target sum exists, print the subset
        result = [set[i] for i in range(n) if subset[i]]
        return result
    else:
        return None



io = remote("35.238.116.121", "32581")

for turn in range(100):
    io.recvuntil(f"Stage {turn+1}\n")
    data = io.recvline().rstrip().decode().split()
    arr = data[:-1]
    s = data[-1]
    arr = [int(i) for i in arr]
    s = int(s)
    brute = 1 # lmao
    if turn == 0:
        io.sendline(b'0')
        continue
    subset = solve_subset(arr, s, brute)
    if subset == None:
        subset = is_subset_sum(arr, s)
    print(subset)
    res = []
    for i in subset:
        res.append(str(arr.index(i)))
    io.sendline(f"{' '.join(res)}")

io.interactive()

#DEAD{T00_B1g_Number_Causes_Pr0blem...}