#!/usr/bin/env python3

from pwn import *

exe = ELF("./re-alloc_revenge_patched")
libc = ELF("./libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so")
ld = ELF("./ld-2.29.so")

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
