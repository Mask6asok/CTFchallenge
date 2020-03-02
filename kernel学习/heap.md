# Linux Kernel Heap Brief Exploit

内核堆与用户堆有所区别，内核中的堆块处理函数有以下四个

- kmaloc
- kfree
- vmalloc
- vfree

其中kamlloc与vmalloc的区别是

1. vmalloc分配高端内存，只有内存不够时才分配低端内存；kmalloc分配低端内存
2. vmalloc分配的物理地址不连续；kmalloc分配的物理地址连续；两者分配的虚拟地址都连续
3. vmalloc一般分配大块内存；kmalloc分配小块内存（不大于128k）

kmalloc分配的chunk由kfree释放，vmalloc分配的chunk由vfree释放

## kmalloc

函数原型：

```c
void *kmalloc(size_t size, gfp_t flags)；
```

常用的flags：

- **GFP_ATOMIC** —— 分配内存的过程是一个原子过程，分配内存的过程不会被（高优先级进程或中断）打断；
- **GFP_KERNEL** —— 正常分配内存；
- **GFP_DMA** —— 给 DMA 控制器分配内存，需要使用该标志（DMA要求分配虚拟地址和物理地址连续）。

flags 的参考用法：
　|– 进程上下文，可以睡眠　　　　　GFP_KERNEL
　|– 进程上下文，不可以睡眠　　　　GFP_ATOMIC
　|　　|– 中断处理程序　　　　　　　GFP_ATOMIC
　|　　|– 软中断　　　　　　　　　　GFP_ATOMIC
　|　　|– Tasklet　　　　　　　　　GFP_ATOMIC
　|– 用于DMA的内存，可以睡眠　　　GFP_DMA | GFP_KERNEL
　|– 用于DMA的内存，不可以睡眠　　GFP_DMA |GFP_ATOMIC

对应的内存释放函数：

```c
void kfree(const void *objp);
```

还有一个包装函数：

```c
static inline void *kzalloc(size_t size, gfp_t flags){    
    return kmalloc(size, flags | __GFP_ZERO);
}
```

该函数会对申请得到的内存区域清零

## vmalloc

函数原型：

```c
void *vmalloc(unsigned long size);
```

对应的内存释放函数

```c
void vfree(const void *addr);
```

## Slab Allocator

Linux Kernel有三种不同的内存分配器：SLAB、SLUB和SLOB。这三者都是slab的实现

slab结构是alsb操作的最小单元，Cache_chain连接了所有kmem_cache结构，每个kmem_cache结构中有一个slabs列表，包含三种slab：

- slabs_full：完全分配的slab
- slabs_partial：部分分配的slab
- slabs_empty：空slab，未分配

slabs列表中的每个slab中的内存空间会被划分为多个chunk使用

![     图  1. slab 分配器的主要结构](https://www.ibm.com/developerworks/cn/linux/l-linux-slab-allocator/figure1.gif)

### SLAB

SLAB是由一页或者多页连续内存中的slab分配出的cache组成的，每个cache对应了Kernel中的一个内存分配结构，也可以说SLAB是一组相同类型的内存结构

SLAB结构如下

```c
struct slab
{
    union
    {
        struct
        {
            struct list_head list;
            unsigned long colouroff;
            void *s_mem;            /* including colour offset */
            unsigned int inuse;     /* num of objs active in slab */
            kmem_bufctl_t free;
            unsigned short nodeid;
        };

        struct slab_rcu __slab_cover_slab_rcu;
    };
};
```

list变量用来将这个struct slab放置在三个slabs之一，s_mem指向第一个存放实际申请的chunk的槽，free是指向下一个自由slab对象

SLAB中的slab组成是

1. slab结构（元数据）
2. slab对象

如下图是6个同类型的结构放在相邻的两页中

![img](https://mk0resourcesinfm536w.kinstacdn.com/wp-content/uploads/111913_1518_ExploitingL1.png)

因此针对SLAB的溢出攻击，也就是针对slab对象的溢出攻击

在一个slab溢出通常发生在向kmalloc出来的chunk写数据时越界，溢出的结果可能是

- 修改邻近的slab
- 如果这个slab的chunk在一页的末尾，则溢出到下一页，

### SLUB

Linux Kernel中的默认内存分配就是SLUB，它弥补了SLAB的一些缺陷

SLUB不像SLAB一样在每个slab开头都放了元数据，而是在每个页的的结构体中，

结构如下

```c
struct page
{
    ...

    struct
    {
        union
        {
            pgoff_t index; /* Our offset within mapping. */
            void *freelist; /* slub first free object */
        };
        ...
        struct
        {
            unsigned inuse:16;
            unsigned objects:15;
            unsigned frozen:1;
        };
        ...
    };
    ...
    union
    {
        ...
        struct kmem_cache *slab; /* SLUB: Pointer to slab */
        ...
    };
    ...
};
```

一个page中的freelist指向第一个自由slab对象，这个自由slab对象又有另外一个freelist指向下一个自由slab对象，有点类似于fastbin的结构

![1580355199735](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580355199735.png)

SLUB分配器管理着内存中许多动态分配的chunk，他们之间的区别也是由size区分，与GLIBC中的fastbin一样，这些大小也有一个定数，假如`kmalloc(50)`，则会返回`kmalloc-64`的chunk

使用，下面命令可以查看更详细的数据

```shell
sudo cat /proc/slabinfo 
...
kmalloc-8192    
kmalloc-4096    
kmalloc-2048    
kmalloc-1024    
kmalloc-512     
kmalloc-256     
kmalloc-192     
kmalloc-128     
kmalloc-96      
kmalloc-64      
kmalloc-32      
kmalloc-16      
kmalloc-8       
```

由于结构相似，SLUB的攻击方式也是来源于slab对象溢出，其与SLAB的攻击方式同源

但是针对SLUB，还有一种不同的利用方法，修改元数据，slab是可以不用对齐的，这样通过修改一个自由对象的元数据的低位有效字节，指向slab内部，然后利用重叠的slab对象来修改元数据，进一步劫持执行流

### SLOB

SLOB主要用于一些内存有限的微机系统，比如嵌入式LInux，其将所有分配的chunk放置在三个链表连接的页面上，这里不加以讨论了

## Vul KVM

先写一个带有漏洞功能的内核模块

heap_vul.c内容如下

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define add 0x1001
#define del 0x1002
#define see 0x1003
#define fix 0x1004


struct add_struct{
    unsigned int len;
    char *content;
};
struct del_struct{
    unsigned int idx;
};
struct see_struct{
    unsigned int idx;
    char *content;
    unsigned int len;
};
struct fix_struct{
    unsigned int idx;
    unsigned int len;
    char *content;
};
void *list[20];
int idx;

void heap_vul_release(struct inode *inode, struct file *file){
    unsigned int i = 0;
    for(i = 0; i < 10; i++){
        if(list[i]){
            kfree(list[i]);
            printk("kfree chunk %d at %p\n", i, list[i]);
            list[i] = 0;
        }
    }
    idx = 0;
}
void _add(struct add_struct *args){
    if(idx < 10){ 
        list[idx] = kmalloc(args->len, GFP_KERNEL);
        memcpy(list[idx], args->content, args->len);
        printk("kamlloc chunk %d at %px\n", idx, list[idx]);
        idx++;
    }else{
        printk("List is full.\n");
    }
}
void _del(struct del_struct *args){
    int i = args->idx;
    if(i >= 0 && i < idx && list[i]){
        kfree(list[i]);
        // list[i] = 0;
        printk("kfree chunk %d at %p\n", i, list[i]);
    }else{
        printk("Index error.\n");
    }
}
void _see(struct see_struct *args){
    int i = args->idx;
    if(i >= 0 && i < idx && list[i]){
        printk(list[i]);
        copy_to_user(args->content, list[i], strlen(list[i]));
        printk("\nOK\n");
    }else{
        printk("Index error.\n");
    }
}
void _fix(struct fix_struct *args)
{
    unsigned int i = args->idx;
    unsigned int len = args->len;
    if(i >= 0 && i < idx && list[i]){
        if(len > strlen(list[i])){
            len = strlen(list[i]);
        }
        copy_from_user(list[i], args->content, len);
        printk("OK\n");
    }else{
        printk("Index error.\n");
    }
}
void heap_vul_ioctl(struct file *file, unsigned int cmd, char *args){
    switch(cmd){
    case add:
        _add(args);
        break;
    case del:
        _del(args);
        break;
    case see:
        _see(args);
        break;
    case fix:
        _fix(args);
        break;
    default:
        printk("ERROR\n");
        break;
    }
}

struct file_operations fops;

static int __init heap_vul_init(void){
    printk(KERN_ALERT "heap_vul driver init!\n");
    fops.unlocked_ioctl = heap_vul_ioctl;
    fops.release = heap_vul_release;
    create_proc_entry("heap_vul", 0666, 0)->proc_fops = &fops;
    return 0;
}

static void __exit heap_vul_exit(void){
    printk(KERN_ALERT "heap_vul driver exit\n");
}

module_init(heap_vul_init);
module_exit(heap_vul_exit);
```

利用LKM实现了一个堆题常见套路，存在的漏洞有

1. free后未置0
2. fix功能长度不受限制

由于我对内核的堆管理机制还不是很熟练，所以这里就简单的利用UAF来提权，等以后熟悉了管理机制再写更全面的利用方法

## Exploit

先尝试申请两个chunk，看看地址

![1580437468491](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580437468491.png)

可以发现，第二次得到的chunk地址与第一次的chunk地址是反过来的，我们看看这地址里面是什么东西

![1580437620877](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580437620877.png)

可以发现它是类似fastbin的结构，LIFO原则，单链表，那我们尝试一下double free

![1580437877075](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580437877075.png)

可以发现，double free是可以的，申请到一样的chunk，接着尝试一下fastbin attack来修改next指针，也即是在2这个chunk修改了值

```c
    _add(0x10, "0");
    _add(0x10, "1");
    _del(0);
    _del(0);
    join_data(0xdeadbeef);
    _add(0x10, payload);
    _add(0x10, "3");
    _add(0x10, "4");
```

在4这个chunk申请时gdb跟进，可以发现0xdeadbeef确实进入了kernel heap管理系统，不过报错了

![1580438722287](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580438722287.png)

我们换一个可访问地址，比如LKM的数据段，劫持到list变量，可以发现成功劫持

![1580439962386](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580439962386.png)

则配合see和fix功能可以实现内核任意地址读写，这里我们直接劫持内核中的file_operations结构体，修改realese函数指针（原本指向heap_vul_release，在关闭LKM时释放所有chunk），指向用户程序，则在关闭LKM时劫持执行流到用户程序，进而提权

![1580440467228](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580440467228.png)

get_root程序和ret2usr一样，提权并且返回到起shell函数

![1580440577263](C:\Users\MoZha\AppData\Roaming\Typora\typora-user-images\1580440577263.png)

当然我们也可以使用溢出来修改相邻chunk的next指针

# Reference

https://resources.infosecinstitute.com/exploiting-linux-kernel-heap-corruptions-slub-allocator/

https://www.ibm.com/developerworks/cn/linux/l-linux-slab-allocator/index.html

https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part3.html

https://argp.github.io/2012/01/03/linux-kernel-heap-exploitation/

http://www.phrack.org/issues/64/6.html

http://retme.net/index.php/2014/06/19/SLAB-ATTACK.html

http://phrack.org/issues/64/6.html#article

http://kernelbof.blogspot.com/2009/07/even-when-one-byte-matters.html