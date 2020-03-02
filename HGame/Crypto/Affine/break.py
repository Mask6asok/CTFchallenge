TABLE = 'zxcvbnmasdfghjklqwertyuiop1234567890QWERTYUIOPASDFGHJKLZXCVBNM'
MOD = len(TABLE)
begin = "hgame"
code = "xr1AJ7havGTpH410"
for A in range(0, 200):
    for B in range(0, 200):
        ciper = ""
        for b in begin:
            i = TABLE.find(b)
            ii = (A * i + B) % MOD
            ciper += TABLE[ii]
        if ciper == "A8I5z":
            print(A, B)
            plain = ""
            for b in code:
                for i in TABLE:
                    i = TABLE.find(i)
                    ii = (A * i + B) % MOD
                    if TABLE[ii] == b:
                        plain += TABLE[i]
                        break
            print(plain)
