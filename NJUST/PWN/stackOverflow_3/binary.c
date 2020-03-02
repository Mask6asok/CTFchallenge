#include<stdio.h>

void magic()
{
  system("/bin/sh");
}

int main()
{
  char buf[16];
  puts("Welcome to NUST-Tp0t OJ~");
  puts("There is a magic door,but how can you open it?");
  printf("Give you a key:%p\n",&magic);
  printf("Please tell me your answer:");
  scanf("%s",&buf);
  puts("Thanks,I will try it.");
}
// gcc binary.c -fno-stack-protector -fpie -pie -o pwn
