for i in xrange(0, 1264):
	base=08048438
	if Byte(base+i)==0x31 and Byte(base+i+3)<=0x5:
		for j in range(Byte(base+i+3)):
			PatchByte(base+i+1+3+j, 0x90)