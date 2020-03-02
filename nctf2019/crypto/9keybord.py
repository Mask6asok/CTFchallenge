tab={
    '2': 'a',
    '22': 'b',
    '222': 'c',
    '2222':' ',
    '3': 'd',
    '33': 'e',
    '333': 'f',
    '3333':' ',
    '4': 'g',
    '44': 'h',
    '444': 'i',
    '4444':' ',
    '5': 'j',
    '55': 'k',
    '555': 'l',
    '5555':' ',
    '6': 'm',
    '66': 'n',
    '666': 'o',
    '6666':' ',
    '7': 'p',
    '77': 'q',
    '777': 'r',
    '7777': 's',
    '8': 't',
    '88': 'u',
    '888': 'v',
    '8888':' ',
    '9': 'w',
    '99': 'x',
    '999': 'y',
    '9999':'z'
}

msg='ooo yyy ii w uuu ee uuuu yyy uuuu y w uuu i i rr w i i rr rrr uuuu rrr uuuu t ii uuuu i w u rrr ee www ee yyy eee www w tt ee'
kay9=[2,3,4,5,6,7,8,9]
code=['o','y','i','w','u','e','r','t']


def permutations(indices):
    # indices = list(range(n))
    global msg
    print (indices)
    n=len(indices)
    while True:
        low_index = n-1
        while low_index > 0 and indices[low_index-1] > indices[low_index]:
            low_index -= 1
        if low_index == 0:
            break
        low_index -= 1
        high_index = low_index+1
        while high_index < n and indices[high_index] > indices[low_index]:
            high_index += 1
        high_index -= 1
        indices[low_index], indices[high_index] = indices[
            high_index], indices[low_index]
        indices[low_index+1:] = reversed(indices[low_index+1:])
        temp = msg
        for i in range(len(code)):
            temp = temp.replace(code[i], str(indices[i]))
        temp = temp.split()
        flag = ""
        for i in temp:
            flag += tab[i]
        if flag.find(' ') != -1:
            continue
        print(flag)
        

permutations(kay9)