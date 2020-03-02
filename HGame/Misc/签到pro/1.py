tab = 'abcdefghijklmnopqrstuvwxyz'
ctoi = lambda x: tab.index(x)
itoc = lambda x: tab[x]

code = "RdjxfwxjfimknztswntzixtjrwmxsfjtjmywtrtntwhffyhjnsxfqjFjfjnbrgfiyykwtbsnkmtmxajsdwqjfmkjywlviHtqzqsGsffywjjyynfyssmxfjypnyihjn".lower(
)
key = "JRFVJYFZVRUAGMAI".lower()


def decode(text, key):
    ans = ''
    j = 0
    for i in text.lower():
        ans += itoc((ctoi(i) - ctoi(key[j % len(key)])) % 26)
        # print(ctoi(i), ctoi(key[j % len(key)]))
        j += 1
    return ans


for i in range(6):
    code = decode(code, key)
    print(code)

# print(decode(code, key))
