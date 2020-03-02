# 已有 public key 与 encode 得到 plaintext
import rsa
from Crypto.PublicKey import RSA
import base64


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


# yafu or http://factordb.com
p = 282164587459512124844245113950593348271
q = 366669102002966856876605669837014229419
e = 65537
n = 103461035900816914121390101299049044413950405173712170434161686539878160984549
# pub = RSA.importKey(open('key.pub').read())
# print(pub)
# n = (pub.n)
# e = (pub.e)
# print(n)
# print(e)

if not p and not q:
    print('Need get p,q')
    exit(0)

d = egcd((p - 1) * (q - 1), e)[2]
if d < 0:
    d += (p - 1) * (q - 1)

enc = 0xad939ff59f6e70bcbfad406f2494993757eee98b91bc244184a377520d06fc35 
plain = pow(enc,d,n)
key = RSA.construct((n, e, d))    # 如果e较小，e应转化成long型: e = long(e)
key.exportKey()
open("private.pem", "wb").write(key.exportKey())


p = open("private.pem").read()
privkey = rsa.PrivateKey.load_pkcs1(p)
crypto = base64.b64decode(open("flag.txt").read())
message = rsa.decrypt(crypto, privkey)
print(message)
