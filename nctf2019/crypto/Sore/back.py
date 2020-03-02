from string import ascii_letters
flag = "NCTF{vlbeunuozbpycklsjXlfpaq}"
key = flag.strip('NCTF{}')
ciper = open("ciphertext.txt", "r").read()
'''字母表
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
'''
print key
len_key = len(key)
print len_key
print len(ciper)
code = list()
print ciper
for j in range(23):
    m = ''
    i = j
    while (i < len(ciper)):
        m += ciper[i]
        i += 23
    code.append(m)
for i in code:
    print i

