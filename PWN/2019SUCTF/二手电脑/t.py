a = list("04SyD1C!")
b = list("Qf(>qwd!")
a[7] = '!'
i = 6
while i >= 0:
    for j in range(32, 128):
        t = ((j | ord(a[i+1])) & ~(j & ord(a[i+1])) | (i)) & ~((j | ord(a[i+1])) & ~(j & ord(a[i+1])) & (i))
        if t == ord(b[i]):
            a[i] = chr(j)
            break
    i -= 1

for i in a:
    print(i, end='')
