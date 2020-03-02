#include<stdio.h>
#include<stdlib.h>

int main()
{

  printf("Welcome to NUST-Tp0t OJ~\n");
  printf("Here is a very easy challenge for you.\n"); 
  //volatile int a=0;
  volatile int a=0;
  volatile char name[16];
  printf("So please tell me your name:");
  scanf("%s",&name);
  printf("OK,I will check,goodbye %s\n",name);
  if(a==0xdeadbeef)
  {
    system("/bin/sh");
  }
}
//gcc binary.c -m32 -fno-stack-protector -o binary
