#include<stdio.h>

void magic()
{
  system("/bin/sh");
}

int main()
{
  setvbuf(stdin,0,2,0);
  setvbuf(stdout,0,2,0);
  char buf[16];
  puts("Welcome to NUST-Tp0t OJ~");
  puts("There is a magic door,but how can you open it?");
  printf("Please tell me your answer:");
  scanf("%s",&buf);
  puts("Thanks,I will try it.");
}
