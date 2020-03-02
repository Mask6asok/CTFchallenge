from pwn import *
context.log_level = 'debug'
def permutations(indices):
    #
    # 
    indices = list(range(indices))
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
        indices[low_index + 1 :] = reversed(indices[low_index + 1 :])
        print indices
        flag = ""
        for i in indices:
            flag += tab[i]
        flag = "nctf{D" + flag + "}"
        if flag == "nctf{DLCTEAM-x1cteam&SU}":
            pause()
        p = process("./tsb")
        p.recvuntil(" flag:")
        p.sendline(flag)
        if p.recv().find("TTT") != -1:
            break
        p.close()
        '''
        temp = msg
        for i in range(len(code)):
            temp = temp.replace(code[i], str(indices[i]))
        temp = temp.split()
        flag = ""
        for i in temp:
            flag += tab[i]
        if flag.find(' ') != -1:
            continue
        print (flag)
        '''
        
tab = ['L','C','TEAM','-','x1cteam','SU''&']
permutations(len(tab))