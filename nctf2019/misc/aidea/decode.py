from PIL import Image
img1 = Image.open("to_do.png")
img2 = Image.open("to.png")
flag = Image.open("to.png")
src1 = img1.convert("RGB")
src2 = img2.convert("RGB")
data1 = src1.load()
data2 = src2.load()

out=[[0 for i in range(300)] for i in range(300)]

print(img1.size, img1.format)
print(img2.size, img2.format)

def check(x, y):
    if (data1[x, y] == data2[x, y]):
        # print(data1[x, y],'-',data2[x, y])
        out[x][y] = 255
    else:
        out[x][y] = 0
    
for i in range(290):
    for j in range(289):
        check(i, j)

for i in range(290):
    for j in range(289):
        flag.putpixel((i, j), (out[i][j],) * 4)
flag = flag.convert("RGB")
flag.save("flag.png")