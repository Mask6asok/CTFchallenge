import random
random.seed(1581860414)
with open("test", 'w') as f:
    for i in range(100):
        f.write(str(random.getrandbits(32)) + "\n")
    f.close()
