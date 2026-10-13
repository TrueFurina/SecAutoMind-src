# encoding=utf-8
import random
from Crypto.Util.number import *
from fractions import gcd

def encrypt(msg, pkey):
    msg, cipher = bin(bytes_to_long(msg))[2:], []
    x, N = pkey
    for bi in msg:
        while True:
            r = random.randint(1, N)
            if gcd(r, N) == 1:
                br = bin(r)[2:]
                c = (pow(x, int(br + bi, 2), N) * r ** 2) % N
                cipher.append(c)
                break
    return cipher


def make_key( nbit):
    while True:
        p, q = getPrime(nbit), getPrime(nbit)
        N, phi = p * q, (p-1)*(q-1)
        x = random.randint(1, N)
        if (N % 8 == 1) and (phi % 8 == 4) and (p != q):
            if pow(q ** 2 * x, (p-1)//2, p) + pow(p ** 2 * x, (q-1)//2, q) == N - phi - 1:
                break
    return (x, N), phi


nbit = 1024

flag="***********************"
pkey,phi = make_key(nbit)
enc = encrypt(flag, pkey)
print(phi)
print(pkey[1])
print(enc)
