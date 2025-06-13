from tool import *

n = 45; q = next_prime(2^14); h = 6; beta = 20; k = 30; tau = 30;

A, c, u, s = gen_instance(n, q, h, m = tau * n)


A_k, c_k, u_k, B = dim_error_tradeoff(A, c, u, beta, h, k)


print(Mitm_on_LWE(A_k, c_k, u_k, B, h))