ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x4010c0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          318208 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         14
  Size of section headers:           64 (bytes)
  Number of section headers:         38
  Section header string table index: 37

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .note.gnu.property NOTE            0000000000400350 000350 000040 00   A  0   0  8
  [ 2] .note.gnu.build-id NOTE            0000000000400390 000390 000024 00   A  0   0  4
  [ 3] .interp           PROGBITS        00000000004003b4 0003b4 00001f 00   A  0   0  1
  [ 4] .gnu.hash         GNU_HASH        00000000004003d8 0003d8 000024 00   A  5   0  8
  [ 5] .dynsym           DYNSYM          0000000000400400 000400 000150 18   A  6   1  8
  [ 6] .dynstr           STRTAB          0000000000400550 000550 0000e9 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          000000000040063a 00063a 00001c 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         0000000000400658 000658 000050 00   A  6   1  8
  [ 9] .rela.dyn         RELA            00000000004006a8 0006a8 000078 18   A  5   0  8
  [10] .rela.plt         RELA            0000000000400720 000720 0000c0 18  AI  5  23  8
  [11] .init             PROGBITS        0000000000401000 001000 000017 00  AX  0   0  4
  [12] .plt              PROGBITS        0000000000401020 001020 000090 10  AX  0   0 16
  [13] .plt.got          PROGBITS        00000000004010b0 0010b0 000008 08  AX  0   0  8
  [14] .text             PROGBITS        00000000004010c0 0010c0 000299 00  AX  0   0 16
  [15] .fini             PROGBITS        000000000040135c 00135c 000009 00  AX  0   0  4
  [16] .rodata           PROGBITS        0000000000402000 002000 000014 00   A  0   0  4
  [17] .eh_frame_hdr     PROGBITS        0000000000402014 002014 00003c 00   A  0   0  4
  [18] .eh_frame         PROGBITS        0000000000402050 002050 0000dc 00   A  0   0  8
  [19] .note.ABI-tag     NOTE            000000000040212c 00212c 000020 00   A  0   0  4
  [20] .init_array       INIT_ARRAY      0000000000403d70 002d70 000008 08  WA  0   0  8
  [21] .fini_array       FINI_ARRAY      0000000000403d78 002d78 000008 08  WA  0   0  8
  [22] .dynamic          DYNAMIC         0000000000403d80 002d80 000200 10  WA  6   0  8
  [23] .got              PROGBITS        0000000000403f80 002f80 000080 08  WA  0   0  8
  [24] .data             PROGBITS        0000000000404000 003000 000010 00  WA  0   0  8
  [25] .bss              NOBITS          0000000000404010 003010 000008 00  WA  0   0  1
  [26] .comment          PROGBITS        0000000000000000 003010 000036 01  MS  0   0  1
  [27] .debug_aranges    PROGBITS        0000000000000000 003050 000150 00      0   0 16
  [28] .debug_info       PROGBITS        0000000000000000 0031a0 00057b 00      0   0  1
  [29] .debug_abbrev     PROGBITS        0000000000000000 00371b 0002ff 00      0   0  1
  [30] .debug_line       PROGBITS        0000000000000000 003a1a 001138 00      0   0  1
  [31] .debug_str        PROGBITS        0000000000000000 004b52 0381b8 01  MS  0   0  1
  [32] .debug_line_str   PROGBITS        0000000000000000 03cd0a 00114f 01  MS  0   0  1
  [33] .debug_macro      PROGBITS        0000000000000000 03de59 00f566 00      0   0  1
  [34] .debug_rnglists   PROGBITS        0000000000000000 04d3bf 000042 00      0   0  1
  [35] .symtab           SYMTAB          0000000000000000 04d408 000378 18     36  10  8
  [36] .strtab           STRTAB          0000000000000000 04d780 0001fc 00      0   0  1
  [37] .shstrtab         STRTAB          0000000000000000 04d97c 00017e 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)

There are no section groups in this file.

Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  PHDR           0x000040 0x0000000000400040 0x0000000000400040 0x000310 0x000310 R   0x8
  INTERP         0x0003b4 0x00000000004003b4 0x00000000004003b4 0x00001f 0x00001f R   0x1
      [Requesting program interpreter: ./bin/lib/ld-linux-x86-64.so.2]
  LOAD           0x000000 0x0000000000400000 0x0000000000400000 0x0007e0 0x0007e0 R   0x1000
  LOAD           0x001000 0x0000000000401000 0x0000000000401000 0x000365 0x000365 R E 0x1000
  LOAD           0x002000 0x0000000000402000 0x0000000000402000 0x00014c 0x00014c R   0x1000
  LOAD           0x002d70 0x0000000000403d70 0x0000000000403d70 0x0002a0 0x0002a8 RW  0x1000
  DYNAMIC        0x002d80 0x0000000000403d80 0x0000000000403d80 0x000200 0x000200 RW  0x8
  NOTE           0x000350 0x0000000000400350 0x0000000000400350 0x000040 0x000040 R   0x8
  NOTE           0x000390 0x0000000000400390 0x0000000000400390 0x000024 0x000024 R   0x4
  NOTE           0x00212c 0x000000000040212c 0x000000000040212c 0x000020 0x000020 R   0x4
  GNU_PROPERTY   0x000350 0x0000000000400350 0x0000000000400350 0x000040 0x000040 R   0x8
  GNU_EH_FRAME   0x002014 0x0000000000402014 0x0000000000402014 0x00003c 0x00003c R   0x4
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10
  GNU_RELRO      0x002d70 0x0000000000403d70 0x0000000000403d70 0x000290 0x000290 R   0x1

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp 
   02     .note.gnu.property .note.gnu.build-id .interp .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt 
   03     .init .plt .plt.got .text .fini 
   04     .rodata .eh_frame_hdr .eh_frame .note.ABI-tag 
   05     .init_array .fini_array .dynamic .got .data .bss 
   06     .dynamic 
   07     .note.gnu.property 
   08     .note.gnu.build-id 
   09     .note.ABI-tag 
   10     .note.gnu.property 
   11     .eh_frame_hdr 
   12     
   13     .init_array .fini_array .dynamic .got 

Dynamic section at offset 0x2d80 contains 27 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000001d (RUNPATH)            Library runpath: [./bin/lib]
 0x000000000000000c (INIT)               0x401000
 0x000000000000000d (FINI)               0x40135c
 0x0000000000000019 (INIT_ARRAY)         0x403d70
 0x000000000000001b (INIT_ARRAYSZ)       8 (bytes)
 0x000000000000001a (FINI_ARRAY)         0x403d78
 0x000000000000001c (FINI_ARRAYSZ)       8 (bytes)
 0x000000006ffffef5 (GNU_HASH)           0x4003d8
 0x0000000000000005 (STRTAB)             0x400550
 0x0000000000000006 (SYMTAB)             0x400400
 0x000000000000000a (STRSZ)              233 (bytes)
 0x000000000000000b (SYMENT)             24 (bytes)
 0x0000000000000015 (DEBUG)              0x0
 0x0000000000000003 (PLTGOT)             0x403f80
 0x0000000000000002 (PLTRELSZ)           192 (bytes)
 0x0000000000000014 (PLTREL)             RELA
 0x0000000000000017 (JMPREL)             0x400720
 0x0000000000000007 (RELA)               0x4006a8
 0x0000000000000008 (RELASZ)             120 (bytes)
 0x0000000000000009 (RELAENT)            24 (bytes)
 0x000000000000001e (FLAGS)              BIND_NOW
 0x000000006ffffffb (FLAGS_1)            Flags: NOW
 0x000000006ffffffe (VERNEED)            0x400658
 0x000000006fffffff (VERNEEDNUM)         1
 0x000000006ffffff0 (VERSYM)             0x40063a
 0x0000000000000000 (NULL)               0x0

Relocation section '.rela.dyn' at offset 0x6a8 contains 5 entries:
    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend
0000000000403fd8  0000000200000006 R_X86_64_GLOB_DAT      0000000000000000 __libc_start_main@GLIBC_2.34 + 0
0000000000403fe0  0000000300000006 R_X86_64_GLOB_DAT      0000000000000000 _ITM_deregisterTMCloneTable + 0
0000000000403fe8  0000000d00000006 R_X86_64_GLOB_DAT      0000000000000000 printf@GLIBC_2.2.5 + 0
0000000000403ff0  0000000700000006 R_X86_64_GLOB_DAT      0000000000000000 __gmon_start__ + 0
0000000000403ff8  0000000b00000006 R_X86_64_GLOB_DAT      0000000000000000 _ITM_registerTMCloneTable + 0

Relocation section '.rela.plt' at offset 0x720 contains 8 entries:
    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend
0000000000403f98  0000000100000007 R_X86_64_JUMP_SLOT     0000000000000000 __isoc23_strtoul@GLIBC_2.38 + 0
0000000000403fa0  0000000400000007 R_X86_64_JUMP_SLOT     0000000000000000 __stack_chk_fail@GLIBC_2.4 + 0
0000000000403fa8  0000000500000007 R_X86_64_JUMP_SLOT     0000000000000000 srand@GLIBC_2.2.5 + 0
0000000000403fb0  0000000600000007 R_X86_64_JUMP_SLOT     0000000000000000 __isoc23_scanf@GLIBC_2.38 + 0
0000000000403fb8  0000000800000007 R_X86_64_JUMP_SLOT     0000000000000000 time@GLIBC_2.2.5 + 0
0000000000403fc0  0000000900000007 R_X86_64_JUMP_SLOT     0000000000000000 mprotect@GLIBC_2.2.5 + 0
0000000000403fc8  0000000a00000007 R_X86_64_JUMP_SLOT     0000000000000000 exit@GLIBC_2.2.5 + 0
0000000000403fd0  0000000c00000007 R_X86_64_JUMP_SLOT     0000000000000000 rand@GLIBC_2.2.5 + 0
No processor specific unwind information to decode

Symbol table '.dynsym' contains 14 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __isoc23_strtoul@GLIBC_2.38 (2)
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.34 (3)
     3: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTable
     4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __stack_chk_fail@GLIBC_2.4 (4)
     5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND srand@GLIBC_2.2.5 (5)
     6: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __isoc23_scanf@GLIBC_2.38 (2)
     7: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     8: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND time@GLIBC_2.2.5 (5)
     9: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mprotect@GLIBC_2.2.5 (5)
    10: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND exit@GLIBC_2.2.5 (5)
    11: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable
    12: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND rand@GLIBC_2.2.5 (5)
    13: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.2.5 (5)

Symbol table '.symtab' contains 37 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS abi-note.c
     2: 000000000040212c    32 OBJECT  LOCAL  DEFAULT   19 __abi_tag
     3: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS init.c
     4: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS static-reloc.c
     5: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS deepDive.c
     6: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS 
     7: 0000000000403d80     0 OBJECT  LOCAL  DEFAULT   22 _DYNAMIC
     8: 0000000000402014     0 NOTYPE  LOCAL  DEFAULT   17 __GNU_EH_FRAME_HDR
     9: 0000000000403f80     0 OBJECT  LOCAL  DEFAULT   23 _GLOBAL_OFFSET_TABLE_
    10: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __isoc23_strtoul@GLIBC_2.38
    11: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.34
    12: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTable
    13: 0000000000404000     0 NOTYPE  WEAK   DEFAULT   24 data_start
    14: 0000000000404010     0 NOTYPE  GLOBAL DEFAULT   24 _edata
    15: 000000000040135c     0 FUNC    GLOBAL HIDDEN    15 _fini
    16: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __stack_chk_fail@GLIBC_2.4
    17: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.2.5
    18: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND srand@GLIBC_2.2.5
    19: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __isoc23_scanf@GLIBC_2.38
    20: 0000000000404000     0 NOTYPE  GLOBAL DEFAULT   24 __data_start
    21: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
    22: 0000000000404008     0 OBJECT  GLOBAL HIDDEN    24 __dso_handle
    23: 0000000000402000     4 OBJECT  GLOBAL DEFAULT   16 _IO_stdin_used
    24: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND time@GLIBC_2.2.5
    25: 0000000000404018     0 NOTYPE  GLOBAL DEFAULT   25 _end
    26: 00000000004010e2     1 FUNC    GLOBAL HIDDEN    14 _dl_relocate_static_pie
    27: 00000000004010c0    34 FUNC    GLOBAL DEFAULT   14 _start
    28: 0000000000404010     0 NOTYPE  GLOBAL DEFAULT   25 __bss_start
    29: 0000000000401233   294 FUNC    GLOBAL DEFAULT   14 begone_dynelf
    30: 0000000000401196   157 FUNC    GLOBAL DEFAULT   14 main
    31: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mprotect@GLIBC_2.2.5
    32: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND exit@GLIBC_2.2.5
    33: 0000000000404010     0 OBJECT  GLOBAL HIDDEN    24 __TMC_END__
    34: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable
    35: 0000000000401000     0 FUNC    GLOBAL HIDDEN    11 _init
    36: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND rand@GLIBC_2.2.5

Histogram for `.gnu.hash' bucket list length (total of 2 buckets):
 Length  Number     % of total  Coverage
      0  1          ( 50.0%)
      1  1          ( 50.0%)    100.0%

Version symbols section '.gnu.version' contains 14 entries:
 Addr: 0x000000000040063a  Offset: 0x0000063a  Link: 5 (.dynsym)
  000:   0 (*local*)       2 (GLIBC_2.38)    3 (GLIBC_2.34)    1 (*global*)   
  004:   4 (GLIBC_2.4)     5 (GLIBC_2.2.5)   2 (GLIBC_2.38)    1 (*global*)   
  008:   5 (GLIBC_2.2.5)   5 (GLIBC_2.2.5)   5 (GLIBC_2.2.5)   1 (*global*)   
  00c:   5 (GLIBC_2.2.5)   5 (GLIBC_2.2.5)

Version needs section '.gnu.version_r' contains 1 entry:
 Addr: 0x0000000000400658  Offset: 0x00000658  Link: 6 (.dynstr)
  000000: Version: 1  File: libc.so.6  Cnt: 4
  0x0010:   Name: GLIBC_2.2.5  Flags: none  Version: 5
  0x0020:   Name: GLIBC_2.4  Flags: none  Version: 4
  0x0030:   Name: GLIBC_2.34  Flags: none  Version: 3
  0x0040:   Name: GLIBC_2.38  Flags: none  Version: 2

Displaying notes found in: .note.gnu.property
  Owner                Data size 	Description
  GNU                  0x00000030	NT_GNU_PROPERTY_TYPE_0	      Properties: x86 ISA needed: x86-64-baseline, x86 feature used: x86, x86 ISA used: x86-64-baseline

Displaying notes found in: .note.gnu.build-id
  Owner                Data size 	Description
  GNU                  0x00000014	NT_GNU_BUILD_ID (unique build ID bitstring)	    Build ID: eb776dfbf16e7c97b2f696d37ef3a5b3c07fd618

Displaying notes found in: .note.ABI-tag
  Owner                Data size 	Description
  GNU                  0x00000010	NT_GNU_ABI_TAG (ABI version tag)	    OS: Linux, ABI: 3.2.0
