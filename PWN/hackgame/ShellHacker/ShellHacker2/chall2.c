// gcc -m32 -z execstack -fPIE -pie -z now chall2.c -o chall2
int main() {
    char buf[0x200];
    int n, i;
    n = read(0, buf, 0x200);
    if (n <= 0) return 0;
    for (i = 0; i < n; i++) {
        if(!((buf[i] >= 65 && buf[i] <= 90) || (buf[i] >= 48 && buf[i] <= 57))) return 0;
    }
    ((void(*)(void))buf)();
}

/*
PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA
*/
// python ./PYTHON.py x86 ascii uppercase eax --input="sc.bin" > out.bin
/*
PYV

*/



