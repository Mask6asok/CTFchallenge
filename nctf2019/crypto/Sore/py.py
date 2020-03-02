def getKeyLen(cipherText): # 获取密钥长度
    keylength = 1
    maxCount = 0
    for step in range(3,18): # 循环密钥长度
        count = 0
        for i in range(step,len(cipherText)-step):
            if cipherText[i] == cipherText[i+step]: 
                 count += 1
        if count>maxCount:  # 每次保存最大次数的密钥长度
            maxCount = count 
            keylength = step
    return keylength  # 返回密钥长度

def getKey(text,length): # 获取密钥
    key = [] # 定义空白列表用来存密钥
    alphaRate =[0.08167,0.01492,0.02782,0.04253,0.12705,0.02228,0.02015,0.06094,0.06996,0.00153,0.00772,0.04025,0.02406,0.06749,0.07507,0.01929,0.0009,0.05987,0.06327,0.09056,0.02758,0.00978,0.02360,0.0015,0.01974,0.00074]
    matrix =textToList(text,length)
    for i in range(length):
        w = [row[i] for row in matrix] #获取每组密文
        li = countList(w) 
        powLi = [] #算乘积
        for j in range(26):
            Sum = 0.0
            for k in range(26):
                Sum += alphaRate[k]*li[k]
            powLi.append(Sum)
            li = li[1:]+li[:1]#循环移位
        Abs = 100
        ch = ''
        for j in range(len(powLi)):
             if abs(powLi[j] -0.065546)<Abs: # 找出最接近英文字母重合指数的项
                 Abs = abs(powLi[j] -0.065546) # 保存最接近的距离，作为下次比较的基准
                 ch = chr(j+97)
        key.append(ch)
    return key

cipher = open("ciphertext.txt", "r").read()
keylen = getKeyLen(cipher)
key = getKey(cipher, keylen)
print key