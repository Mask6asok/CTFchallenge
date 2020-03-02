#!/usr/bin/env sage
# coding=utf-8

from secret import Co1, Co2, Co3, CoCo1, CoCo2, CoCo3, CoCoCo1, CoCoCo2, CoCoCo3

P = PolynomialRing(GF(2), 'x')
F.<x> = GF(2)[]

def COCO(coco):
    co, cococo = 0, 0
    for ii in coco[::-1]:
        co += int(ii) * x**cococo
        cococo += 1
    return co

class COCOCO():
    def __init__(self, Co, CoCo, CoCoCo):
        self.Co = COCO(bin(Co)[2:])
        self.CoCo = COCO(bin(CoCo)[2:])
        self.CoCoCo = COCO(bin(2**(CoCoCo+1)-1)[2:])
		print self.CoCo
		print self.CoCoCo
    def cococo(self):
        co = 0
        s = self.Co*x
        if s > x**48:
            s -= x**48
        co = s
        a = self.Co.exponents()
        b = self.CoCo.exponents()
        coco = list(set(a).intersection(set(b)))
        cc = 0
        for k in coco:
            cc += x**k
        output = 0
        try:
            oo = cc.exponents()
            l = len(oo)
            if oo[0] == 0:
                l -= 1
            if l%2 == 1:
                output = 1
            else:
                output = 0
        except:
            pass
        e = co.exponents()
        if e[0] == 0 and output == 1:
            co += 1
        if e[0] == 1 and output == 0:
            co -= 1
        self.Co = co
        return output

def cOcO(co,coco,cococo):
    return (co*coco)^(co*cococo)^(coco*cococo)


if __name__=="__main__":
    C1 = COCOCO(int.from_bytes(Co1, "big"), CoCo1, CoCoCo1)
    C2 = COCOCO(int.from_bytes(Co2, "big"), CoCo2, CoCoCo2)
    C3 = COCOCO(int.from_bytes(Co3, "big"), CoCo3, CoCoCo3)

    with open("keystream", "wb") as f:
        for i in range(8192):
            b = 0
            for j in range(8):
                print b,
                b = (b<<1)+cOcO(C1.cococo(), C2.cococo(), C3.cococo())
            f.write(chr(b).encode())
#x^42 + x^26
#x^48 + x^47 + x^46 + x^45 + x^44 + x^43 + x^42 + x^41 + x^40 + x^39 + x^38 + x^37 + x^36 + x^35 + x^34 + x^33 + x^32 + x^31 + x^30 + x^29 + x^28 + x^27 + x^26 + x^25 + x^24 + x^23 + x^22 + x^21 + x^20 + x^19 + x^18 + x^17 + x^16 + x^15 + x^14 + x^13 + x^12 + x^11 + x^10 + x^9 + x^8 + x^7 + x^6 + x^5 + x^4 + x^3 + x^2 + x + 1
#x^35 + x^13
#x^48 + x^47 + x^46 + x^45 + x^44 + x^43 + x^42 + x^41 + x^40 + x^39 + x^38 + x^37 + x^36 + x^35 + x^34 + x^33 + x^32 + x^31 + x^30 + x^29 + x^28 + x^27 + x^26 + x^25 + x^24 + x^23 + x^22 + x^21 + x^20 + x^19 + x^18 + x^17 + x^16 + x^15 + x^14 + x^13 + x^12 + x^11 + x^10 + x^9 + x^8 + x^7 + x^6 + x^5 + x^4 + x^3 + x^2 + x + 1
#x^47 + x^22
#x^48 + x^47 + x^46 + x^45 + x^44 + x^43 + x^42 + x^41 + x^40 + x^39 + x^38 + x^37 + x^36 + x^35 + x^34 + x^33 + x^32 + x^31 + x^30 + x^29 + x^28 + x^27 + x^26 + x^25 + x^24 + x^23 + x^22 + x^21 + x^20 + x^19 + x^18 + x^17 + x^16 + x^15 + x^14 + x^13 + x^12 + x^11 + x^10 + x^9 + x^8 + x^7 + x^6 + x^5 + x^4 + x^3 + x^2 + x + 1