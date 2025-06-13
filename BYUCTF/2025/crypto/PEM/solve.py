from Crypto.PublicKey import RSA
import gmpy2


pub = RSA.importKey(open('ssh_host_rsa_key.pub').read())

print(pub.n)
print(pub.e)

print(gmpy2.iroot(pub.n, 2)[0].to_bytes(200, 'big').rstrip(b'\0'))
