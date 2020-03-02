import subprocess
ans = list()
for seed in range(0, 0xffff):
    count = 0
    keep = seed
    while seed:
        count += 1
        seed &= (seed-1)
    if count == 10:
        ans.append(keep)

print(ans)
for i in ans:
    proc = subprocess.Popen(['./zorro_bin'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out = proc.communicate(('1\n%s\n' % i).encode('utf-8'))[0]
    if "nullcon".encode('utf-8') in out:
        print(out)
