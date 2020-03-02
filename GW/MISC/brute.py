str1 = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
leak = '9CWNdk4jFb'
s1 = str1[::-1]
l = len(leak)
res = ''
for i in range(len(leak)):
    for j in range(len(str1)):
        if leak[i] == str1[j]:
            res += str(j) + ' ' + str(j) + ' ' + '0' + ' ' + str(
                len(str1) - 1) + ' '
            break
print(res)