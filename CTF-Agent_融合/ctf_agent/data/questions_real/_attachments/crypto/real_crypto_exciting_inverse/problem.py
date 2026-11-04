import gmpy2
from Crypto.Util.number import *

nbits = 1024

p = getPrime(nbits)
q = getPrime(nbits)
e = 65537
n = p*q
phi = (p-1)*(q-1)
d = gmpy2.invert(e, phi)
pinv = gmpy2.invert(p, q)
qinv = gmpy2.invert(q, p)
flag = "********************"
m = bytes_to_long(flag)
c = pow(m, e, n)

print(e)
print(phi)
print(c)
print(pinv)
print(qinv)
