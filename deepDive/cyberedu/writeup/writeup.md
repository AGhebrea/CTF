# Premise:
We have an arbitrary read + buffer overflow, non-PIE exe, a canary on the stack, custom libc and ld.

# Steps:
## Setup environment
This is an optional step but you could make the whole dev experience better if you'd just comment out the begone_dynelf function and compile the
source file with this:
```
gcc ./src/deepDive.c -o ./bin/deepDive -no-pie -z now -fstack-protector
```

## Find the libc base address 
We look at the PLTGOT and grab one address. Walk back (To lower addresses) and check to see if we get to ELF magic. When we get to ELF magic we 
have found the base address of libc.

## Parse loaded libc
We parse the program headers (segments), grab the dynamic segment, from the dynamic segment we grab strtab and symtab. We use those to get the address
of system and __environment

We use system address to ultimately do a buffer overflow and return to system.

## Grabbing a stack address
We use __environment to get a stack address. This was an important part of the puzzle. There might be other ways to get a stack address but this was the first that came to mind. 
Now that we have a stack address we must get to the stack frame of the main function.

### Getting main stack frame
You must do a dump of the stack, first of all to get some bearings on where the values that you control are located in memory + to know the canary value.
So let's assume you do a big stack dump.

Stack dump is taken at this moment in time. Where is the main's function stack frame ?
(Taken from objdump of exe)
```
  4011fc:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
  401200:	48 8b 00             	mov    rax,QWORD PTR [rax]
```

To get our bearings let's ask ourselves what is the life of the program ? _start gets called, we can see that the only function call in _start is
to __libc_start_main and return address is 0x4010e1:
```
  4010db:	ff 15 f7 2e 00 00    	call   QWORD PTR [rip+0x2ef7]        # 403fd8 <__libc_start_main@GLIBC_2.34>
  4010e1:	f4                   	hlt
```
We can find the return address in the stack dump.
We have found __libc_start_main stack frame. The issue now is that technically you don't know how many
other functions are called before main. You could dump the code from the remote and analyze it but that is 
not necessary and is faster to figure it out w/o analyzing the libc code.

So we found __libc_start_main stack frame. We then make the observation that the leak happens after strtoul is called
we should find the ret value in the stack dump, we search for 0x4011f8, we find it.
Let's take an example:
I find it at address 0x7ffecc2c91e8, so I know that at the time of the strtoul call RSP is 0x7ffecc2c91e8 + 8
and I can see that the prologue of main is:
```
  401196:	55                   	push   rbp
  401197:	48 89 e5             	mov    rbp,rsp
  40119a:	48 83 ec 30          	sub    rsp,0x30
  40119e:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
  4011a5:	00 00 
  4011a7:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
```
so we have RBP = RSP + 0x30 = 0x7ffecc2c9220
then we can see that inside of main we take the address of input which is RBP-0x20 and write into it
which is 0x7ffecc2c9200
Canary value is at RBP-8
"input" address is RBP-0x20 and grows towards RBP and beyond.
We now know how to read the canary and to inspect stack layout.

### POP RDI gadget: 
Let's not forget about the gadget
We do the same old ELF parsing incantations and we get the address of the libc executable segment (aka the code).
We dump it to a file and let ropper rip on it
```
ropper --nocolor -a x86_64 -r -f ./doc/libcexe.bin > ./doc/bins/libc.rops.txt
```
We then search for the most convenent gadget which i believe is "pop RDI; ret" and use it.

## The exploit
We have what we need to return to system("/bin/sh"), we just need to glue it together.
So, we must have in RDI a pointer to the string "/bin/sh\0".
It's easier to see in the sol.py:ret2() code but in essence:
Knowing all about the stack frame we can place canary at correct location, set next RBP to user controlled address,
set first return address to POP RDI gadget, then place on the stack a pointer to *sh* string, address of system and
the *sh* string. When the instructions execute rdi will get loaded to a pointer to "/bin/sh\n" and then system("/bin/sh") 
will get called.
