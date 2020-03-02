#include<stdio.h>

int main()
{
  int seed = 0;
  srand(seed);
  for(int i = 0; i < 10; i++)
  {
    printf("%d,", rand() % 6 + 1);
  }
  return 0;
}
