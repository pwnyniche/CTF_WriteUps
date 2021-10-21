#!/usr/bin/env python3

from pwn import *

exe = ELF("./proxy_patched")
libc = ELF("./libc-2.31.so?token=eyJ1c2VyX2lkIjo5MTAsInRlYW1faWQiOjEzMywiZmlsZV9pZCI6NX0.YWoutw.0WDNa8YruuFIi7KK8iRz6DiVGDI")
ld = ELF("./ld-2.31.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
