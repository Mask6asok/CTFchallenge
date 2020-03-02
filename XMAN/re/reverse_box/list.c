#include <stdio.h>
int ror(int num, int size)
{
    char tp = 0;
    for (int i = 0; i < size; i++)
    {
        tp += 1 << i;
    }
    tp = num & tp;
    num = num >> size;
    tp = tp << (8 - size);
    return num | tp;
}
int main()
{
    unsigned int v1;    // eax
    int v2;             // edx
    char v3;            // al
    char v4;            // ST1B_1
    char v5;            // al
    int result;         // eax
    unsigned __int8 v7; // [esp+1Ah] [ebp-Eh]
    char v8;            // [esp+1Bh] [ebp-Dh]
    char v9;            // [esp+1Bh] [ebp-Dh]
    int v10;            // [esp+1Ch] [ebp-Ch]

    int bp = 156;
    for (int bp = 0xd9; bp <= 0xd9; bp++)
    {
        // printf("%d\n",bp);
        int list[256] = {0};
        list[0] = bp;

        char bVar1;
        unsigned __seed;
        char local_12;
        char local_11;
        local_12 = 1;
        local_11 = 1;
        do
        {
            if ((char)local_12 < '\0')
            {
                bVar1 = 0x1b;
            }
            else
            {
                bVar1 = 0;
            }
            local_12 = bVar1 ^ local_12 * '\x02' ^ local_12;
            bVar1 = local_11 ^ local_11 * '\x02';
            bVar1 = bVar1 ^ bVar1 << 2;
            bVar1 = bVar1 ^ bVar1 << 4;
            if (bVar1 < '\0')
            {
                local_11 = 9;
            }
            else
            {
                local_11 = 0;
            }
            local_11 = local_11 ^ bVar1;
            list[local_12] = (list[0] ^ local_11 ^ (bVar1 >> 7 | local_11 << 1) ^ (bVar1 >> 6 | local_11 << 2) ^ (bVar1 >> 5 | local_11 << 3) ^ (bVar1 >> 4 | local_11 << 4)) & 0xff;
        } while (local_12 != 1);
        for(int i=0;i<256;i++)
        {
            printf("%d,",list[i]);
        }
    }
    return result;
}
