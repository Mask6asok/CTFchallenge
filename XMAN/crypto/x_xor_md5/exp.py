data = open("xmd5", 'rb')

# key = list(bytes('xLž27ûºË', 'utf-8'))
key = [1, 120, 12, 76, 16, 158, 50, 55, 18, 12, 251, 186, 203, 143, 106, 83]
print(key)
for i in range(7):
    for j in range(16):
        c = data.read(1)
        k = key[j]
        a = ord(c) ^ k
        print(chr(a), end='')
    print("")

for i in key:
    print(hex(i^0x20).replace("0x",""),end='')