from pwn import *
from pyzbar.pyzbar import decode
from PIL import Image


def getQR():
    im = Image.new("RGB", (38, 38), 'white')
    pixels = im.load()
    y = 0
    x = 0
    for i in range (0,19):
        qr = P.recvline()
        j = 8
        while x < 37:
            if qr[j] == 0xa0:
                pixels[x, y] = (255, 255, 255)
                pixels[x, y + 1] = (255, 255, 255)
                x += 1
            if qr[j] == 0x88:
                pixels[x, y] = (0, 0, 0)
                pixels[x, y + 1] = (0, 0, 0)
                x += 1
            if qr[j] == 0x80:
                pixels[x, y] = (0, 0, 0)
                pixels[x, y + 1] = (255, 255, 255)
                x += 1
            if qr[j] == 0x84:
                pixels[x, y] = (255, 255, 255)
                pixels[x, y + 1] = (0, 0, 0)
                x += 1
            j += 1
        y += 2
        x = 0

    # write out QR to disk
    im.save('qr.png')
    print(decode(Image.open('./qr.png')))

    # ugly hack because ctf
    # popen('zbarimg ./qr.png > qr.out')
    #
    # with open('qr.out') as f:
    #     data = f.readline()
    #     f.close()
    #
    # m = re.findall(r'Code:([0-9a-f]*)', data)
    # return m[0]


def pwn():
    global P
    P = remote('125.235.240.166', 20123)  # start the vuln binary
    P.recvuntil(b':')
    P.recvline()
    P.recvline()
    P.recvline()

    getQR()
    P.interactive()
    # P.recvuntil(b':')
    # P.recvline()
    # P.recvline()
    # P.recvline()
    #
    # try:
    #     while 1:
    #         getQR()
    # except KeyboardInterrupt:
    #     P.interactive()


pwn()