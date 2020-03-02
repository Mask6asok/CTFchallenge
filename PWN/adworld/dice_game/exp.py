from pwn import *
context.log_level = 'debug'
p = process("./dice_game")
p = remote("111.198.29.45","55358")
p.sendline('\x00' * 0x50)
p.recv()
ans = [
    2, 5, 4, 2, 6, 2, 5, 1, 4, 2, 3, 2, 3, 2, 6, 5, 1, 1, 5, 5, 6, 3, 4, 4, 3,
    3, 3, 2, 2, 2, 6, 1, 1, 1, 6, 4, 2, 5, 2, 5, 4, 4, 4, 6, 3, 2, 3, 3, 6, 1
]

for i in range(50):
    p.sendline(str(ans[i]))
    p.recv()

p.interactive()
