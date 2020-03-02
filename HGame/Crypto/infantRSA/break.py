# -*- coding: utf-8 -*-
import gmpy2
from Crypto.Util.number import bytes_to_long, long_to_bytes
p = 681782737450022065655472455411
q = 675274897132088253519831953441
e = 13
n = p * q
c = 275698465082361070145173688411496311542172902608559859019841
d = gmpy2.invert(e, (p - 1) * (q - 1))
m = pow(c, d, n)
print long_to_bytes(m)
