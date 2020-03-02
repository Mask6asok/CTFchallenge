flag = ""
enc_flag = "g{jehm$L5p+ItamU_muR3!A}0!inTPeT"
tmp = "hgame{ABCDEFGHIJKLMNOPQRSTUVWXY}"
enc_tmp = "g{AehHCJFIEGDamBLPQOKXS}VYUWTMNR"
for i in tmp:
    flag += enc_flag[enc_tmp.find(i)]
print flag
