from string import ascii_letters
from flag import flag


ctoi = lambda x: ascii_letters.index(x)
itoc = lambda x: ascii_letters[x]

# ascii_letters='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

key = flag.strip('NCTF{}')
len_key = len(key) # brute len

plaintext = open('plaintext.txt', 'r').read()

plain = ''.join(p for p in plaintext if p in ascii_letters)

# plain char is in ascii_letters

# enumerate(plain) 索引序列： i序号 p是字符

cipher += itoc:	读tab中位置处字符
			参数模52
			p转成index再加上key中第i个：循环

按照plain的长度，将plain中每一个字符与flag的字符（循环）相加再模52

cipher = ''.join( itoc( ( ctoi(p) + ctoi( key[i % len_key] ) ) % 52 )  for i,p in enumerate(plain) )

open('ciphertext.txt', 'w').write(cipher)

c=p+f

