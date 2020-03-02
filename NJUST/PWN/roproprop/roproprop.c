#include<stdio.h>
int main()
{
  setvbuf(stdin,0,2,0);
  setvbuf(stdout,0,2,0);
  char buf[10];
  puts("Welcome to NUST-Tp0t OJ~");
  puts("This time wo have no backdoor,also,no shellcode.");
  puts("It is all about ROP.");
  printf("Try it:");
  gets(&buf);
  puts("Wait for your good news!");
}
