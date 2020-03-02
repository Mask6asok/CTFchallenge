#include<stdio.h>
int main()
{
  char buf[50];
  puts("Welcome to NUST-Tp0t OJ~");
  puts("This time we have no backdoor.");
  puts("But i hope you build it!");
  printf("How to do it:");
  scanf("%50s",&buf);
  puts("I will try.");
  void (*fp)(void);
  fp=(void *)buf;
  fp();
  return 0;
}
