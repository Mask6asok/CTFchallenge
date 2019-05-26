import re


def getchr():
    str = '363534333231305F65646362613938376D6C6B6A696867667574737271706F6E4342417A797877764B4A494847464544535251504F4E4D4C2B5A595857565554'
    res = re.findall(r'.{2}', str)

    c = 1
    strtab = ''
    for i in res:
        strtab += chr(int('0x'+i, 16))
    print(strtab)


getchr()
