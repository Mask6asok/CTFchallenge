flag = list("rctf[wELDN<UTWHTIKEY ]*")
for i in range(len(flag)):
    if i == 30:
        i = i
    if ord(flag[i]) in range(ord('0'), ord('9')+1):
        continue
    if ord(flag[i]) in range(ord('a'), ord('z')+1):
        continue
    if ord(flag[i]) in range(ord('A'), ord('Z')+1):
        continue
    flag[i] = chr(ord(flag[i]) ^ 0x20)

print("".join(flag))
# rctf{wE1L_D0N3_6UT_WH4T_I5_that}