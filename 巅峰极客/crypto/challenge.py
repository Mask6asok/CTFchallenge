from Crypto.Util.number import *
from Crypto.Random.random import *
from flag import flag

Co = getStrongPrime(1024)
CoCo = getStrongPrime(1024)
CoCoCo = getStrongPrime(1024)


def CoCoCoCo(Co, CoCo):
    while CoCo: Co, CoCo = CoCo, Co % CoCo
    return Co


def CoCoCoCoCo(Co, CoCo, CoCoCo):
    CoCoCoCo = 1
    while CoCo != 0:
        if (CoCo & 1) == 1:
            CoCoCoCo = (CoCoCoCo * Co) % CoCoCo
        CoCo >>= 1
        Co = (Co * Co) % CoCoCo
    return CoCoCoCo


CoCoCoCoCoCoCoCo = CoCoCoCoCo(CoCoCo, Co, CoCo)
while True:
    CoCoCoCoCoCoCoCoCo = randint(1, 2 ** 512)
    if CoCoCoCo(CoCoCoCoCoCoCoCoCo, CoCo - 1) == 1:
        break
CoCoCoCoCoCo = bytes_to_long("CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo")
CoCoCoCoCoCoCoCoCoCo = CoCoCoCoCo(CoCoCo, CoCoCoCoCoCoCoCoCo, CoCo)
CoCoCoCoCoCoCoCoCoCoCo = (CoCoCoCoCoCo * CoCoCoCoCo(CoCoCoCoCoCoCoCo, CoCoCoCoCoCoCoCoCo, CoCo)) % CoCo
CoCoCoCoCoCoCo = bytes_to_long(flag)
CoCoCoCoCoCoCoCoCoCoCoCo = (CoCoCoCoCoCoCo * CoCoCoCoCo(CoCoCoCoCoCoCoCo, CoCoCoCoCoCoCoCoCo, CoCo)) % CoCo
with open('cipher.txt', 'w') as f:
    f.write("CoCoCoCoCoCoCoCoCoCo = " + str(CoCoCoCoCoCoCoCoCoCo) + "\n")
    f.write("CoCoCo = " + str(CoCoCo) + "\n")
    f.write("CoCoCoCoCoCoCoCoCoCoCo = " + str(CoCoCoCoCoCoCoCoCoCoCo) + "\n")
    f.write("CoCo = " + str(CoCo) + "\n")
    f.write("CoCoCoCoCoCoCoCoCoCoCoCo = " + str(CoCoCoCoCoCoCoCoCoCoCoCo) + "\n")
