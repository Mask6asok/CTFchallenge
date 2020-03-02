#include<stdio.h>
int main()
{
  setvbuf(stdin,0,2,0);
  setvbuf(stdout,0,2,0);
  puts("Welcome to guess 1.0");
  puts("I will give you a number which is 0 or 1 in each round");
  puts("And there will be 3 round");
  puts("If you can catch all of them, you are superman");
  int seed,num;
  seed=time(0);
  srand(seed);
  int i;
  for(i=0;i<3;i++)
  {
    int a=rand()&1;
    printf("%d round > ",i+1);
    scanf("%d",&num);
    if(num!=a)
    {
      break;
    }
  }
  if(i==3)
  {
    system("/bin/sh");
  }else
  {
    puts("You are CXK!");
  }
  return 0;
}
