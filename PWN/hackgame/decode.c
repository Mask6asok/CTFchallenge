#include <iostream>

__int64 decode(unsigned int *a1, signed int a2, __int64 a3)
{
    unsigned int v3;  // ST34_4
    unsigned int *v4; // rax
    unsigned int *v5; // rax
    __int64 result;   // rax
    unsigned int v7;  // ST30_4
    unsigned int *v8; // rax
    unsigned int v9;  // ST30_4
    int v10;          // [rsp+Ch] [rbp-2Ch]
    int v11;          // [rsp+20h] [rbp-18h]
    unsigned int v12; // [rsp+20h] [rbp-18h]
    int v13;          // [rsp+24h] [rbp-14h]
    int v14;          // [rsp+24h] [rbp-14h]
    unsigned int j;   // [rsp+28h] [rbp-10h]
    unsigned int i;   // [rsp+28h] [rbp-10h]
    unsigned int v17; // [rsp+2Ch] [rbp-Ch]
    unsigned int v18; // [rsp+2Ch] [rbp-Ch]
    unsigned int v19; // [rsp+30h] [rbp-8h]
    unsigned int v20; // [rsp+34h] [rbp-4h]

    if (a2)
    {
        if (a2 <= 1)
        {
            if (a2 < -1)
            {
                v10 = -a2;
                v14 = 52 / -a2 + 6;
                v18 = -1640531527 * v14;
                v20 = *a1;
                do
                {
                    v12 = (v18 >> 2) & 3;
                    for (i = v10 - 1; i; --i)
                    {
                        v7 = a1[i - 1];
                        v8 = &a1[i];
                        *v8 -= ((v20 ^ v18) + (v7 ^ *(int *)(4LL * (v12 ^ i & 3) + a3))) ^ ((4 * v20 ^ (v7 >> 5)) + ((v20 >> 3) ^ 16 * v7));
                        v20 = *v8;
                    }
                    v9 = a1[v10 - 1];
                    *a1 -= ((4 * v20 ^ (v9 >> 5)) + ((v20 >> 3) ^ 16 * v9)) ^ ((v20 ^ v18) + (v9 ^ *(int *)(4LL * v12 + a3)));
                    result = *a1;
                    v20 = *a1;
                    v18 += 1640531527;
                    --v14;
                } while (v14);
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
                for (j = 0; j < a2 - 1; ++j)
                {
                    v3 = a1[j + 1];
                    v4 = &a1[j];
                    *v4 += ((v3 ^ v17) + (v19 ^ *(int *)(4LL * (v11 ^ j & 3) + a3))) ^ ((4 * v3 ^ (v19 >> 5)) + ((v3 >> 3) ^ 16 * v19));
                    v19 = *v4;
                }
                v5 = &a1[a2 - 1];
                *v5 += ((*a1 ^ v17) + (v19 ^ *(int *)(4LL * (v11 ^ j & 3) + a3))) ^ ((4 * *a1 ^ (v19 >> 5)) + ((*a1 >> 3) ^ 16 * v19));
                result = *v5;
                v19 = result;
                --v13;
            } while (v13);
        }
    }
    return result;
}

int main()
{
    int a[] = {
        0xa9,
        0x0b,
        0xfc,
        0x5d,
        0xaa,
        0xd9,
        0xb6,
        0xec,
        0x27,
        0x8c,
        0x32,
        0xb9,
        0x0b,
        0xf0,
        0xaf,
        0x6e,
        0xf9,
        0x44,
        0x32,
        0xe2,
        0x33,
        0xb8,
        0x1b,
        0x6c,
        0xa1,
        0xd5,
        0x9c,
        0x8c,
        0x0b,
        0x60,
        0x57,
        0x44,
        0xea,
        0x65,
        0xf5,
        0xb1,
        0x69,
        0x0f,
        0x8f,
        0x9c,
        0x26,
        0x64,
        0x04,
        0x10,
        0x67,
        0xd6,
        0xb9,
        0xa4,
        0x3f,
        0xb1,
        0x7a,
        0x40};
    int b[] = {0xef,
               0xbe,
               0xad,
               0xde,
               0x21,
               0x43,
               0xee,
               0x12,
               0x66,
               0xc6,
               0x12,
               0xbe};
    int n;
    scanf("%d", &n);
    decode(a, n, b);
    printf("%s", a[0]);
}