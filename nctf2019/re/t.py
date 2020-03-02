from pwn import *
from random import *
s = ['L', 'C', 'TEAM', 'x1cteam', 'SU', '&', '-']

def shuffle_str(s):
    shuffle(s)
    return ''.join(s)


while True:
    sh = process("./tsb")
    sh.recvuntil('flag:\n')
    str = "nctf{D" + shuffle_str(s) + "}"
    sh.sendline(str)
    if sh.recv().find('TT') != -1:
        print(str)
        break
    sh.close()