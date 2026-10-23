# Provenance: 西湖论剑2021 中国杭州网络安全技能大赛 CRYPTO SpecialCurve2
# Recovered 2026-08-27 from public writeup (https://cn-sec.com/archives/3093519.html)
# ⚠️ 原始附件(被删的 E:/Program/Cybersecurity/比赛真题/ 文件夹)在脚本注释中给出了
#   本实例的 n / HINT / C 具体值；这些值每次运行随机生成、未留存于任何仓库/文档，
#   故此处仅恢复【挑战脚本模板】，无法复现本实例真值。
#   真值仅以 sha256(cd7e815f4a5a378b8a856ee518a1d7277f306221ce6d68d56dd6f27da2571c4f)
#   形式存于 questions_real JSON，需解出后校验。
from Crypto.Util.number import *
#from flag import flag
import random
def add(P1,P2):
    x1,y1=P1
    x2,y2=P2
    x3=(x1*x2-y1*y2)%n
    y3=(x1*y2+x2*y1)%n
    return (x3,y3)
def mul(P,k):
    assert k>=0
    Q=(1,0)
    while k>0:
        if k%2:
            k-=1
            Q=add(P,Q)
        else:
            k//=2
            P=add(P,P)
    return Q
def getMyPrime():
    while True:
        q=getPrime(88)
        p=2*q+1
        if isPrime(p):
            return p
e=getPrime(256)
n=getMyPrime()*getMyPrime()*getMyPrime()
print('n=%d'%n)
G=(1,1)
HINT=mul(G,e)
print('HINT=%s'%str(HINT))
x=bytes_to_long(flag[7:39])
y=bytes_to_long(flag[39:-1])
M=(x,y)
C=mul(M,e)
print('C=%s'%str(C))
