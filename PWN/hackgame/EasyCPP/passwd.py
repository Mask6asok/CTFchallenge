# p455w0rd

tab = [0x44, 0x00, 0x02, 0x41, 0x43, 0x47, 0x10, 0x63, 0x00]


def check(a, b, i):
    if (((a | b) & ~(a & b) | i) & ~((a | b) & ~(a & b) & i)) == tab[i]:
        return True
    return False


flag = "flag{{{}}}"

i = 0
for a in range(32, 127):
    for b in range(32, 127):
        if check(a, b, i):
            for c in range(32, 127):
                if check(b, c, i + 1):
                    for d in range(32, 127):
                        if check(c, d, i + 2):
                            for e in range(32, 127):
                                if check(d, e, i + 3):
                                    for f in range(32, 127):
                                        if check(e, f, i + 4):
                                            for g in range(32, 127):
                                                if check(f, g, i + 5):
                                                    for h in range(32, 127):
                                                        if check(g, h, i + 6):
                                                            if check(h, 0, i+7):
                                                                flag = flag.format(
                                                                    chr(a)+chr(b)+chr(c)+chr(d)+chr(e)+chr(f)+chr(g)+chr(h))

print(flag)
