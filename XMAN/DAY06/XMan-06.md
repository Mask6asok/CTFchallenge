# XMan-06

今天还是胖的一天



上午讲了格式化字符串的利用



## 格式化字符串函数 

常见的有格式化字符串函数有

- 输入
  - scanf
- 输出

| 函数                      | 基本介绍                               |
| ------------------------- | -------------------------------------- |
| printf                    | 输出到 stdout                          |
| fprintf                   | 输出到指定 FILE 流                     |
| vprintf                   | 根据参数列表格式化输出到 stdout        |
| vfprintf                  | 根据参数列表格式化输出到指定 FILE 流   |
| sprintf                   | 输出到字符串                           |
| snprintf                  | 输出指定字节数到字符串                 |
| vsprintf                  | 根据参数列表格式化输出到字符串         |
| vsnprintf                 | 根据参数列表格式化输出指定字节到字符串 |
| setproctitle              | 设置 argv                              |
| syslog                    | 输出日志                               |
| err, verr, warn, vwarn 等 | 。。。                                 |

其基本格式如下

```
%[parameter][flags][field width][.precision][length]type
```

- parameter
  - n$，获取格式化字符串中的指定参数
- flag
- field width
  - 输出的最小宽度
- precision
  - 输出的最大长度
- length，输出的长度
  - hh，输出一个字节
  - h，输出一个双字节
- type
  - d/i，有符号整数
  - u，无符号整数
  - x/X，16 进制 unsigned int 。x 使用小写字母；X 使用大写字母。如果指定了精度，则输出的数字不足时在左侧补 0。默认精度为 1。精度为 0 且值为 0，则输出为空。
  - o，8 进制 unsigned int 。如果指定了精度，则输出的数字不足时在左侧补 0。默认精度为 1。精度为 0 且值为 0，则输出为空。
  - s，如果没有用 l 标志，输出 null 结尾字符串直到精度规定的上限；如果没有指定精度，则输出所有字节。如果用了 l 标志，则对应函数参数指向 wchar_t 型的数组，输出时把每个宽字符转化为多字节字符，相当于调用 wcrtomb 函数。
  - c，如果没有用 l 标志，把 int 参数转为 unsigned char 型输出；如果用了 l 标志，把 wint_t 参数转为包含两个元素的 wchart_t 数组，其中第一个元素包含要输出的字符，第二个元素为 null 宽字符。
  - p， void * 型，输出对应变量的值。printf("%p",a) 用地址的格式打印变量 a 的值，printf("%p", &a) 打印变量 a 所在的地址。
  - n，不输出字符，但是把已经成功输出的字符个数写入对应的整型指针参数所指的变量。
  - %， '`%`'字面值，不接受任何 flags, width。

## 格式化字符串漏洞利用

其实，在上一部分，我们展示了格式化字符串漏洞的两个利用手段

- 使程序崩溃，因为 %s 对应的参数地址不合法的概率比较大。
- 查看进程内容，根据 %d，%f 输出了栈上的内容。

下面我们会对于每一方面进行更加详细的解释。

### 程序崩溃

通常来说，利用格式化字符串漏洞使得程序崩溃是最为简单的利用方式，因为我们只需要输入若干个 %s 即可

```
%s%s%s%s%s%s%s%s%s%s%s%s%s%s
```

这是因为栈上不可能每个值都对应了合法的地址，所以总是会有某个地址可以使得程序崩溃。这一利用，虽然攻击者本身似乎并不能控制程序，但是这样却可以造成程序不可用。比如说，如果远程服务有一个格式化字符串漏洞，那么我们就可以攻击其可用性，使服务崩溃，进而使得用户不能够访问。

### 泄露内存 

利用格式化字符串漏洞，我们还可以获取我们所想要输出的内容。一般会有如下几种操作

- 泄露栈内存
  - 获取某个变量的值
  - 获取某个变量对应地址的内存
- 泄露任意地址内存
  - 利用 GOT 表得到 libc 函数地址，进而获取 libc，进而获取其它 libc 函数地址
  - 盲打，dump 整个程序，获取有用信息。

### 覆盖内存

上面，我们已经展示了如何利用格式化字符串来泄露栈内存以及任意地址内存，那么我们有没有可能修改栈上变量的值呢，甚至修改任意地址变量的内存呢? 答案是可行的，只要变量对应的地址可写，我们就可以利用格式化字符串来修改其对应的数值。这里我们可以想一下格式化字符串中的类型

```
%n,不输出字符，但是把已经成功输出的字符个数写入对应的整型指针参数所指的变量。
```

通过这个类型参数，再加上一些小技巧，我们就可以达到我们的目的，这里仍然分为两部分，一部分为覆盖栈上的变量，第二部分为覆盖指定地址的变量。

```
...[overwrite addr]....%[overwrite offset]$n
```

其中... 表示我们的填充内容，overwrite addr 表示我们所要覆盖的地址，overwrite offset 地址表示我们所要覆盖的地址存储的位置为输出函数的格式化字符串的第几个参数。所以一般来说，也是如下步骤

- 确定覆盖地址
- 确定相对偏移
- 进行覆盖

讲完格式化字符串也讲了一些安全机制绕过方式，如ASLR、NX、Canary

## Canary 原理 [¶](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/mitigation/canary-zh/#canary_1)

### 在 GCC 中使用 Canary

可以在 GCC 中使用以下参数设置 Canary:

```
-fstack-protector 启用保护，不过只为局部变量中含有数组的函数插入保护
-fstack-protector-all 启用保护，为所有函数插入保护
-fstack-protector-strong
-fstack-protector-explicit 只对有明确stack_protect attribute的函数开启保护
-fno-stack-protector 禁用保护.
```

### Canary 实现原理 

开启 Canary 保护的 stack 结构大概如下

```
        High
        Address |                 |
                +-----------------+
                | args            |
                +-----------------+
                | return address  |
                +-----------------+
        rbp =>  | old ebp         |
                +-----------------+
      rbp-8 =>  | canary value    |
                +-----------------+
                | 局部变量        |
        Low     |                 |
        Address
```

当程序启用 Canary 编译后，在函数序言部分会取 fs 寄存器 0x28 处的值，存放在栈中 %ebp-0x8 的位置。 这个操作即为向栈中插入 Canary 值，代码如下：

```
mov    rax, qword ptr fs:[0x28]
mov    qword ptr [rbp - 8], rax
```

在函数返回之前，会将该值取出，并与 fs:0x28 的值进行异或。如果异或的结果为 0，说明 canary 未被修改，函数会正常返回，这个操作即为检测是否发生栈溢出。

```
mov    rdx,QWORD PTR [rbp-0x8]
xor    rdx,QWORD PTR fs:0x28
je     0x4005d7 <main+65>
call   0x400460 <__stack_chk_fail@plt>
```

如果 canary 已经被非法修改，此时程序流程会走到 `__stack_chk_fail`。`__stack_chk_fail` 也是位于 glibc 中的函数，默认情况下经过 ELF 的延迟绑定，定义如下。

```
eglibc-2.19/debug/stack_chk_fail.c

void __attribute__ ((noreturn)) __stack_chk_fail (void)
{
  __fortify_fail ("stack smashing detected");
}

void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
                    msg, __libc_argv[0] ?: "<unknown>");
}
```

这意味可以通过劫持 `__stack_chk_fail`的 got 值劫持流程或者利用 `__stack_chk_fail` 泄漏内容 (参见 stack smash)。

进一步，对于 Linux 来说，fs 寄存器实际指向的是当前栈的 TLS 结构，fs:0x28 指向的正是 stack_guard。



```
typedef struct
{
  void *tcb;        /* Pointer to the TCB.  Not necessarily the
                       thread descriptor used by libpthread.  */
  dtv_t *dtv;
  void *self;       /* Pointer to the thread descriptor.  */
  int multiple_threads;
  uintptr_t sysinfo;
  uintptr_t stack_guard;
  ...
} tcbhead_t;
```

如果存在溢出可以覆盖位于 TLS 中保存的 Canary 值那么就可以实现绕过保护机制。



事实上，TLS 中的值由函数 security_init 进行初始化。



```
static void
security_init (void)
{
  // _dl_random的值在进入这个函数的时候就已经由kernel写入.
  // glibc直接使用了_dl_random的值并没有给赋值
  // 如果不采用这种模式, glibc也可以自己产生随机数

  //将_dl_random的最后一个字节设置为0x0
  uintptr_t stack_chk_guard = _dl_setup_stack_chk_guard (_dl_random);

  // 设置Canary的值到TLS中
  THREAD_SET_STACK_GUARD (stack_chk_guard);

  _dl_random = NULL;
}

//THREAD_SET_STACK_GUARD宏用于设置TLS
#define THREAD_SET_STACK_GUARD(value) \
  THREAD_SETMEM (THREAD_SELF, header.stack_guard, value)
```

## Canary 绕过技术

### 泄露栈中的 Canary

Canary 设计为以字节 `\x00` 结尾，本意是为了保证 Canary 可以截断字符串。 泄露栈中的 Canary 的思路是覆盖 Canary 的低字节，来打印出剩余的 Canary 部分。 这种利用方式需要存在合适的输出函数，并且可能需要第一溢出泄露 Canary，之后再次溢出控制执行流程。

### one-by-one 爆破 Canary

对于 Canary，不仅每次进程重启后的 Canary 不同 (相比 GS，GS 重启后是相同的)，而且同一个进程中的每个线程的 Canary 也不同。 但是存在一类通过 fork 函数开启子进程交互的题目，因为 fork 函数会直接拷贝父进程的内存，因此每次创建的子进程的 Canary 是相同的。我们可以利用这样的特点，彻底逐个字节将 Canary 爆破出来。 在著名的 offset2libc 绕过 linux64bit 的所有保护的文章中，作者就是利用这样的方式爆破得到的 Canary: 这是爆破的 Python 代码:

```
print "[+] Brute forcing stack canary "

start = len(p)
stop = len(p)+8

while len(p) < stop:
   for i in xrange(0,256):
      res = send2server(p + chr(i))

      if res != "":
         p = p + chr(i)
         #print "\t[+] Byte found 0x%02x" % i
         break

      if i == 255:
         print "[-] Exploit failed"
         sys.exit(-1)


canary = p[stop:start-1:-1].encode("hex")
print "   [+] SSP value is 0x%s" % canary
```

### 劫持__stack_chk_fail 函数 

已知 Canary 失败的处理逻辑会进入到 `__stack_chk_fail`ed 函数，`__stack_chk_fail`ed 函数是一个普通的延迟绑定函数，可以通过修改 GOT 表劫持这个函数。

参见 ZCTF2017 Login，利用方式是通过 fsb 漏洞篡改 `__stack_chk_fail` 的 GOT 表，再进行 ROP 利用

### 覆盖 TLS 中储存的 Canary 值 [¶](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/mitigation/canary-zh/#tls-canary)

已知 Canary 储存在 TLS 中，在函数返回前会使用这个值进行对比。当溢出尺寸较大时，可以同时覆盖栈上储存的 Canary 和 TLS 储存的 Canary 实现绕过。

而ASLR的绕过，通常进行爆破



下午还讲了一些堆的概念，但是碍于我们即使水平不高，堆的一些攻击方式并没有细讲，有点小遗憾