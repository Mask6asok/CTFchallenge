# kernel 2.6.32

ubuntu 16.04安装kernel 2.6.32

由于linux2.6.32版本过于久远，ubuntu 16.04上的gcc和make版本过高，编译总会出一些问题，因此降低make和gcc版本

```shell
sudo apt install gcc-4.7 g++-4.7
sudo rm /usr/bin/gcc /usr/bin/g++
sudo ln -s /usr/bin/gcc-4.7 /usr/bin/gcc
sudo ln -s /usr/bin/g++-4.7 /usr/bin/g++
```
此时gcc版本就是4.7了

```shell
wget https://mirrors.tuna.tsinghua.edu.cn/gnu/make/make-3.80.tar.gz
tar -xvf make-3.80.tar.gz
cd make-3.80/
./configure
make
sudo make install
```

在源码目录下生成了make，稍后编译时使用这个make

```shell
➜  make-3.80 ./make -v  
GNU Make 3.80
Copyright (C) 2002  Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
```

下载了源码后修改三处文件

1. arch/x86/vdso/Makefile中第28行的 `-m elf_x86_64` 改成 `-m64`，第72行的`-m elf_i386`改成`-m32`
2. drivers/net/igbvf/igbvf.h中注释第128行
3. kernel/timeconst.pl中第373行`defined(@val)`改成`@val`

接着就使用3.80的make来make

```shell
~/MAKE/make-3.80/make menuconfig
~/MAKE/make-3.80/make bzImage
...
Root device is (8, 1)
Setup is 15036 bytes (padded to 15360 bytes).
System is 3754 kB
CRC 4505d1c3
Kernel: arch/x86/boot/bzImage is ready  (#1)
```

编译成功