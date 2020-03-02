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
    print(hex(k), end='')
    key.append(chr(k))
print()
print(''.join(key))
