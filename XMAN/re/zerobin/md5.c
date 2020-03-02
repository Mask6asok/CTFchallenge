int main()
{
    srand(seed);
    MD5_Init((__int64)&v10);
    for (idx = 0; idx <= 29; ++idx)
    {
        v9 = rand() % 1000;
        sprintf(&s, "%d", v9);
        v3 = strlen(&s);
        MD5_Update((__int64)&v10, (__int64)&s, v3);
        flag[idx] = v9 ^ LOBYTE(dword_6020C0[idx]);
    }
    flag[idx] = 0;
    MD5_Final(v11, &v10);
    for (idx = 0; idx <= 15; ++idx)
        sprintf(&s1[2 * idx], "%02x", (unsigned __int8)v11[idx]); // 将v11内容写入到s1
}