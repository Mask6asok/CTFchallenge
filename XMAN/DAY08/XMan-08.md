# XMan-08

今天继续盗源码

上午讲了脱壳的一些技巧

壳是在一些计算机软件里也有一段专门负责保护软件不被非法修改或反编译的程序

它们一般都是先于程序运行，拿到控制权，然后完成它们保护软件的任务

一般壳分有压缩壳和加密壳

压缩壳主要是应用于压缩程序大小，如常见的UPX、ASpack，前几天de1ta的逆向题就有一道是脱UPX壳，当时没学，用软件也脱不下来，太菜了

今天学了这个，知道了如何找到程序的OEP，并且在OEP处把整个程序dump下来，就可以利用IDA分析了

结合昨天学的知识，把IAT补全，就可以得到一个正常运行的程序了

例子：

![r0.png](https://i.loli.net/2019/08/08/8gYqcVEeTh7lzX5.png)

![r1.png](https://i.loli.net/2019/08/08/LB965XWIwCUnyJg.png)

一般长地址跳转就是进入OEP

![r2.png](https://i.loli.net/2019/08/08/IcsS8KkENiG1hf3.png)

在OD中bp 0x00435A43下断，再进一步，来到OEP

![r3.png](https://i.loli.net/2019/08/08/9SVvihozegZbx2D.png)

来到了OEP，接着把程序dump下来

![r4.png](https://i.loli.net/2019/08/08/1tD26gTmIwkEz8B.png)

这时候IDA就可以分析了，但是还不能运行，因为各种表没有重构，可以借助正在运行的程序把表重构补齐

![r5.png](https://i.loli.net/2019/08/08/ALrYSoeIjpuFz9M.png)

利用Import REConstructor，attach上OD起的程序（管理员权限），然后输入OEP，AutoSearch->Get Imports->Fix Dump，输入到OD导出的文件，接着就能跑啦



下午的反调试讲的很简略，简单的patch掉check，有点可惜没能深入学



接着讲ELF的结构，在pwn中学过了很多了

不过ret2dl_resolve这一块不是很懂，这次重讲ELF的一些函数表，加深了映象

Linux脱壳这一块也很是牛逼，虽然有现成的upx -d可以脱，但是手动拖懂原理还是有必要的，记录一下

![u0.png](https://i.loli.net/2019/08/08/2kMKivo1QeWErjc.png)

先是利用GDB调试，中断程序看程序映射，搜索ELF魔数，找到解压出来加载的程序，主要不要直接加载源文件

![u1.png](https://i.loli.net/2019/08/08/hqsXjxc2T18DC46.png)

接着可以把解压程序所在段dump出来，分析LOAD

![u2.png](https://i.loli.net/2019/08/08/39IJTVWOmwMNKYo.png)

也可以直接连着把后面几段dump出来

![u3.png](https://i.loli.net/2019/08/08/RkBJEXpQGmF6uY8.png)

拖到IDA可以分析啦

![u4.png](https://i.loli.net/2019/08/08/hcxfWMY8OQuvl5J.png)

今天学到好多！