#include <stdio.h>
typedef long long __int64;
typedef int _DWORD;


__int64 decode(unsigned int *a1, signed int a2, __int64 a3)
{
  unsigned int v3; // ST34_4
  unsigned int *v4; // rax
  unsigned int *v5; // rax
  __int64 result; // rax
  unsigned int v7; // ST30_4
  unsigned int *v8; // rax
  unsigned int v9; // ST30_4
  int v10; // [rsp+Ch] [rbp-2Ch]
  int v11; // [rsp+20h] [rbp-18h]
  unsigned int v12; // [rsp+20h] [rbp-18h]
  int v13; // [rsp+24h] [rbp-14h]
  int v14; // [rsp+24h] [rbp-14h]
  unsigned int j; // [rsp+28h] [rbp-10h]
  unsigned int i; // [rsp+28h] [rbp-10h]
  unsigned int v17; // [rsp+2Ch] [rbp-Ch]
  unsigned int v18; // [rsp+2Ch] [rbp-Ch]
  unsigned int v19; // [rsp+30h] [rbp-8h]
  unsigned int v20; // [rsp+34h] [rbp-4h]

  if ( a2 )
  {
    if ( a2 <= 1 )
    {
      if ( a2 < -1 )
      {
        v10 = -a2;
        v14 = 52 / -a2 + 6;
        v18 = -1640531527 * v14;
        v20 = *a1;
        do
        {
          v12 = (v18 >> 2) & 3;
          for ( i = v10 - 1; i; --i )
          {
            v7 = a1[i - 1];
            v8 = &a1[i];
            *v8 -= ((v20 ^ v18) + (v7 ^ *(_DWORD *)(4LL * (v12 ^ i & 3) + a3))) ^ ((4 * v20 ^ (v7 >> 5))
                                                                                 + ((v20 >> 3) ^ 16 * v7));
            v20 = *v8;
          }
          v9 = a1[v10 - 1];
          *a1 -= ((4 * v20 ^ (v9 >> 5)) + ((v20 >> 3) ^ 16 * v9)) ^ ((v20 ^ v18) + (v9 ^ *(_DWORD *)(4LL * v12 + a3)));
          result = *a1;
          v20 = *a1;
          v18 += 1640531527;
          --v14;
        }
        while ( v14 );
      }
    }
    else
    {
      v13 = 52 / a2 + 6;
      v17 = 0;
      v19 = a1[a2 - 1];
      do
      {
        v17 -= 1640531527;
        v11 = (v17 >> 2) & 3;
        for ( j = 0; j < a2 - 1; ++j )
        {
          v3 = a1[j + 1];
          v4 = &a1[j];
          *v4 += ((v3 ^ v17) + (v19 ^ *(_DWORD *)(4LL * (v11 ^ j & 3) + a3))) ^ ((4 * v3 ^ (v19 >> 5))
                                                                               + ((v3 >> 3) ^ 16 * v19));
          v19 = *v4;
        }
        v5 = &a1[a2 - 1];
        *v5 += ((*a1 ^ v17) + (v19 ^ *(_DWORD *)(4LL * (v11 ^ j & 3) + a3))) ^ ((4 * *a1 ^ (v19 >> 5))
                                                                              + ((*a1 >> 3) ^ 16 * v19));
        result = *v5;
        v19 = result;
        --v13;
      }
      while ( v13 );
    }
  }
  return result;
}




int main(){
    char v0[88];

    *(_DWORD *)&v0[16] = 0x5DFC0BA9;
*(_DWORD *)&v0[20] = 0xECB6D9AA;
*(_DWORD *)&v0[24] = -1187869657;
*(_DWORD *)&v0[28] = 1857024011;
*(_DWORD *)&v0[32] = -500022023;
*(_DWORD *)&v0[36] = 1813755955;
*(_DWORD *)&v0[40] = -1935878751;
*(_DWORD *)&v0[44] = 1146576907;
*(_DWORD *)&v0[48] = -1309317654;
*(_DWORD *)&v0[52] = -1668346007;
*(_DWORD *)&v0[56] = 268723238;
*(_DWORD *)&v0[60] = -1531324825;
*(_DWORD *)&v0[64] = 1081782591;
*(_DWORD *)&v0[68] = -1212119530;
*(_DWORD *)v0 = -559038737;
*(_DWORD *)&v0[4] = 317604641;
*(_DWORD *)&v0[8] = -1106065818;
*(_DWORD *)&v0[12] = -2045625668;
*(_DWORD *)&v0[84] = 0;
int n;
scanf("%d",&n);
decode((unsigned int *)&v0[16], n, (__int64)v0);
printf("%s",v0);
}
