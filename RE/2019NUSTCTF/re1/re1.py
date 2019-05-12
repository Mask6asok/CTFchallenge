
num = []
for i in range(10):
    for j in range(10):
        num.append(i*100+j*10+i)

for a1 in num:
    for a2 in num:
        for a3 in num:
            a4 = (a1+a2+a3)//2
            t = a4*(a4-a1)*(a4-a2)*(a4-a3)
            if t > 0:
                t = int(t**0.5)
                if t == 34257:
                    print(a1, a2, a3)
