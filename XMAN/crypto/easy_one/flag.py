a = list()
b = list()
a1 = open("msg001", 'rb')
b1 = open("msg001.enc", "rb")
for i in range(0x1d):
    a.append(ord(a1.read(1)))
    b.append(ord(b1.read(1)))

key = ['V', ]
for i in range(1, len(a)):
    k = ((b[i]-i*i-a[i]) ^ a[i-1]) & 0x7f
    key.append(chr(k))
key = ''.join(key[0:0x1d-1])
while len(key) < 0x19e:
    key += key
enc_flie = open("msg002.enc", 'rb')
enc = list()
for i in range(0x19e):
    enc.append(ord(enc_flie.read(1)))

flag = list()
flag.append(chr(enc[0]-ord(key[0])))
for i in range(1, 0x19e):
    flag.append(chr((enc[i]-(ord(key[i]) ^ ord(flag[i-1]))-i*i) & 0xff))

print("".join(flag))
