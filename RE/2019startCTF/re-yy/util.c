/*
 * util.c
 * Copyright (C) 2019 hzshang <hzshang15@gmail.com>
 *
 * Distributed under terms of the MIT license.
 */

#include "util.h"
#include "stand.h"


int pc;
unsigned char buffer[0x10];
unsigned char box[]="\x82\x05\x86\x8a\x0b\x11\x96\x1d\x27\xa9\x2b\xb1\xf3\x5e\x37\x38\xc2\x47\x4e\x4f\xd6\x58\xde\xe2\xe5\xe6\x67\x6b\xec\xed\x6f\xf2\x73\xf5\x77\x7f";
//unsigned char box[]="abcdefghijklmnopqrstuvwxyz0123456789";
unsigned char append[]="\x61\x24\x25\x86\x31\xab\x6e\xaf\xb1\x14\xfe\x76\x78\x3d\x1e\xff";
unsigned char table[] = "\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76\xca\x82\xc9\x7d\xfa\x59\x47\xf0\xad\xd4\xa2\xaf\x9c\xa4\x72\xc0\xb7\xfd\x93\x26\x36\x3f\xf7\xcc\x34\xa5\xe5\xf1\x71\xd8\x31\x15\x04\xc7\x23\xc3\x18\x96\x05\x9a\x07\x12\x80\xe2\xeb\x27\xb2\x75\x09\x83\x2c\x1a\x1b\x6e\x5a\xa0\x52\x3b\xd6\xb3\x29\xe3\x2f\x84\x53\xd1\x00\xed\x20\xfc\xb1\x5b\x6a\xcb\xbe\x39\x4a\x4c\x58\xcf\xd0\xef\xaa\xfb\x43\x4d\x33\x85\x45\xf9\x02\x7f\x50\x3c\x9f\xa8\x51\xa3\x40\x8f\x92\x9d\x38\xf5\xbc\xb6\xda\x21\x10\xff\xf3\xd2\xcd\x0c\x13\xec\x5f\x97\x44\x17\xc4\xa7\x7e\x3d\x64\x5d\x19\x73\x60\x81\x4f\xdc\x22\x2a\x90\x88\x46\xee\xb8\x14\xde\x5e\x0b\xdb\xe0\x32\x3a\x0a\x49\x06\x24\x5c\xc2\xd3\xac\x62\x91\x95\xe4\x79\xe7\xc8\x37\x6d\x8d\xd5\x4e\xa9\x6c\x56\xf4\xea\x65\x7a\xae\x08\xba\x78\x25\x2e\x1c\xa6\xb4\xc6\xe8\xdd\x74\x1f\x4b\xbd\x8b\x8a\x70\x3e\xb5\x66\x48\x03\xf6\x0e\x61\x35\x57\xb9\x86\xc1\x1d\x9e\xe1\xf8\x98\x11\x69\xd9\x8e\x94\x9b\x1e\x87\xe9\xce\x55\x28\xdf\x8c\xa1\x89\x0d\xbf\xe6\x42\x68\x41\x99\x2d\x0f\xb0\x54\xbb\x16";
unsigned char key[]="\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c\xa0\xfa\xfe\x17\x88\x54\x2c\xb1\x23\xa3\x39\x39\x2a\x6c\x76\x05\xf2\xc2\x95\xf2\x7a\x96\xb9\x43\x59\x35\x80\x7a\x73\x59\xf6\x7f\x3d\x80\x47\x7d\x47\x16\xfe\x3e\x1e\x23\x7e\x44\x6d\x7a\x88\x3b\xef\x44\xa5\x41\xa8\x52\x5b\x7f\xb6\x71\x25\x3b\xdb\x0b\xad\x00\xd4\xd1\xc6\xf8\x7c\x83\x9d\x87\xca\xf2\xb8\xbc\x11\xf9\x15\xbc\x6d\x88\xa3\x7a\x11\x0b\x3e\xfd\xdb\xf9\x86\x41\xca\x00\x93\xfd\x4e\x54\xf7\x0e\x5f\x5f\xc9\xf3\x84\xa6\x4f\xb2\x4e\xa6\xdc\x4f\xea\xd2\x73\x21\xb5\x8d\xba\xd2\x31\x2b\xf5\x60\x7f\x8d\x29\x2f\xac\x77\x66\xf3\x19\xfa\xdc\x21\x28\xd1\x29\x41\x57\x5c\x00\x6e\xd0\x14\xf9\xa8\xc9\xee\x25\x89\xe1\x3f\x0c\xc8\xb6\x63\x0c\xa6\x03\x8f\x9c\xce\x4d\xb6\x22\x82\xad\x5c\x1b\xa9\xa3\xd9\x8c\x21";
unsigned char result[0xa0];
unsigned long long cmp[]={
    0,0,0x50cf402af81446ae,0x1212068c04fed331,0xc3d961e826c7fa23,0x3df0c71a70453ca9,
    0xac376eab16bcbedf,0x78625df7949c8b14,0x5ad331b21d9816fc,0xa37bca9a86603adc,
    0x09d2ffd9b2f1d5b5,0x021956c03dd777d4,0xe377a2e86c429bb6,0x862aa9914032ac99,
    0x9b415cc33c47faf3,0x9e5a30d4d00705e8,0x44b6adfba39b528d,0x48fe77229c83723f,
    0xffed4e00128486fe,0xca121f84231944ac
};
int cnt;
#define hash(x,y,z) ((27 * ((x^y) >> 7)) ^ ((x^y)<<1) ^ x ^ z)
/*unsigned char hash(unsigned char x,unsigned char y,unsigned char z){
    return ((27 * ((x^y) >> 7)) ^ ((x^y)<<1) ^ x ^ z);
}*/
void encrypt(unsigned char *buf){
    *(long long*)buf ^= *(long long*)key ^ *(long long*)&result[cnt];
    *(long long*)&buf[8] ^= *(long long*)&key[8] ^ *(long long*)&result[cnt+8];
    cnt+=0x10;
    unsigned char p[0x10];
    unsigned char tmp;
    for(int i=0x10;i<0xa0;i+=0x10){
        for(int j=0;j<0x10;j++){
            p[j]=table[buf[j]];
        }
        tmp = p[0] ^ p[5] ^ p[10] ^ p[15];
        buf[0]=hash(p[0],p[5],tmp);
        buf[1]=hash(p[5],p[10],tmp);
        buf[2]=hash(p[10],p[15],tmp);
        buf[3]=hash(p[15],p[0],tmp);

        tmp = p[4] ^ p[9] ^ p[14] ^ p[3];
        buf[4]=hash(p[4],p[9],tmp);
        buf[5]=hash(p[9],p[14],tmp);
        buf[6]=hash(p[14],p[3],tmp);
        buf[7]=hash(p[3],p[4],tmp);

        tmp = p[8] ^ p[13] ^ p[2] ^ p[7];
        buf[8]=hash(p[8],p[13],tmp);
        buf[9]=hash(p[13],p[2],tmp);
        buf[10]=hash(p[2],p[7],tmp);
        buf[11]=hash(p[7],p[8],tmp);

        tmp = p[12] ^ p[1] ^ p[6] ^ p[11];
        buf[12]=hash(p[12],p[1],tmp);
        buf[13]=hash(p[1],p[6],tmp);
        buf[14]=hash(p[6],p[11],tmp);
        buf[15]=hash(p[11],p[12],tmp);
        *(long long*)buf ^= *(long long*)&key[i];
        *(long long*)&buf[8] ^= *(long long*)&key[i+8];
    }
    p[0]=table[buf[0]];
    p[1]=table[buf[5]];
    p[2]=table[buf[10]];
    p[3]=table[buf[15]];

    p[4]=table[buf[4]];
    p[5]=table[buf[9]];
    p[6]=table[buf[14]];
    p[7]=table[buf[3]];

    p[8]=table[buf[8]];
    p[9]=table[buf[13]];
    p[10]=table[buf[2]];
    p[11]=table[buf[7]];

    p[12]=table[buf[12]];
    p[13]=table[buf[1]];
    p[14]=table[buf[6]];
    p[15]=table[buf[11]];
    
    *(long long*)&result[cnt] = *(long long*)p ^ *(long long*)&key[0xa0];
    *(long long*)&result[cnt+8] = *(long long*)&p[8] ^ *(long long*)&key[0xa8];
}













