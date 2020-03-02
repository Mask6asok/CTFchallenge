
def ror(num, size):
    num = num & 0xff
    tp = int('1'*size, 2)
    tp = num & tp
    num = num >> size
    tp = tp << (8-size)
    out = num | tp
    return out


for num in range(0xd9, 0xd9+1):
    a1 = [0 for i in range(256)]
    a1[0] = num
    idx = 1
    v8 = 1
    while True:
        v2 = (idx ^ 2 * idx) & 0xff
        if ((idx & 0x80) == 0):
            v3 = 0
        else:
            v3 = 27
        idx = (v2 ^ v3) & 0xff
        v4 = (4 * (2 * v8 ^ v8) ^ 2 * v8 ^ v8) & 0xff
        v9 = (16 * v4 ^ v4) & 0xff
        if (v9 >= 0):
            v5 = 0
        else:
            v5 = 9
        v8 = v9 ^ v5
        result = ror(v8, 4) ^ ror(v8, 5) ^ ror(v8, 6) ^ ror(v8, 7) ^ (v8 ^ a1[0])
        a1[idx] = result
        if idx == 1:
            break
    # print(hex(a1[ord('T')]))
    # print(hex(a1[ord('W')]))
    # print(hex(a1[ord('C')]))
    # print(hex(a1[ord('T')]))
    # print(hex(a1[ord('F')]))
    print(a1)


'''
95eeaf95ef94234999582f722f492f72b19a7aaf72e6e776b57aee722fe77ab5ad9aaeb156729676ae7a236d99b1df4a
'''
