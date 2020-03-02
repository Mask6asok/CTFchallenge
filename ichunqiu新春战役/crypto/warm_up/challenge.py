from Crypto.Util.number import *
from encode import KEY

q = getPrime(1024)
p = getPrime(1024)
r = getPrime(1024)
s = getPrime(1500)

e1 = 125794
e2 = 42373

n1 = p * q
n2 = p * r
n3 = p * q * s
c1 = pow(s, e1, n1)
Key = int(KEY.encode('hex'), 16)
key_encode = pow(Key, e2, n3)

with open("enc","a")as f:
    f.write("c1: "+str(c1)+"\n")
    f.write("n1: "+str(n1)+"\n")
    f.write("n2: "+str(n2)+"\n")
    f.write("key_encode: "+str(key_encode)+"\n")

