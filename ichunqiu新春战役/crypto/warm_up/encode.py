from flag import flag
import os


KEY = os.urandom(len(flag))
dec = int(flag.encode('hex'), 16)

assert len(bin(dec)[2:]) == 335
mask = int('1' * 335, 2)
dec = (dec ^ dec << 200) & mask
enc = dec ^ bytes_to_long(KEY)
print "enc: "+str(enc)

#enc: 17403902166198774030870481073653666694643312949888760770888896025597904503707411677223946079009696809

