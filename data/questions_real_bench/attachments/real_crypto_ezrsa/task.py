from Crypto.Util.number import *
import gmpy2
import libnum

assert(e<100)

while(gmpy2.gcd((p1-1)*(q1-1),e)!=1):
    p1=getPrime(nbit)
    q1=getPrime(nbit)
    n1=p1*q1
    phi1=(p1-1)*(q1-1)

print(((p2-1)*(q2-1)))
ee=((p2-1)*(q2-1))
while(gmpy2.gcd((p2-1)*(q2-1),e)!=1):
    p2=getPrime(nbit)
    q2=getPrime(nbit)
    n2=p2*q2
    phi2=(p2-1)*(q2-1)

while(gmpy2.gcd((p3-1)*(q3-1),e)!=1):
    p3=getPrime(nbit)
    q3=getPrime(nbit)
    n3=p3*q3
    phi3=(p3-1)*(q3-1)


assert(gmpy2.gcd(e,phi1)==1)
d1=gmpy2.invert(e,phi1)
assert(gmpy2.gcd(e,phi2)==1)
d2=gmpy2.invert(e,phi2)
assert(gmpy2.gcd(e,phi3)==1)
d3=gmpy2.invert(e,phi3)

flag="**************************"

m=libnum.s2n(flag)
print(n1)
print(pow(m,e,n1))
print(n2)
print(pow(m,e,n2))
print(n3)
print(pow(m,e,n3))
