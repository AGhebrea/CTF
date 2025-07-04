#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <time.h>

void begone_dynelf();

int main()
{
    char input[20];
    unsigned long addr = 0;
    
    setvbuf(stdin, NULL, _IONBF, 0); 	
    setvbuf(stdout, NULL, _IONBF, 0); 	
    setvbuf(stderr, NULL, _IONBF, 0);

    begone_dynelf();

    while(1){
        scanf("%[^\n]%*c", input);
        if(input[0] == 'q')
            break;
        addr = strtoul(input, NULL, 16);
        printf("%lu\n", *(long*)addr);
    }
    
    return 0;
}

/* try using dynelf now :) */
void begone_dynelf()
{
    void* printf_address = &printf;
    size_t printf_offset = 0x4b2f9;
    void* libc_addr = printf_address-printf_offset;
    size_t gnu_hash_size = 0x0050d4;
    size_t gnu_hash_offset = 0x3d8;
    void* gnu_hash_addr = libc_addr + gnu_hash_offset;
    size_t firstSegmentSize = 0x023200;
    int stat = 0;

    srand(time(0));

    stat = mprotect(libc_addr, firstSegmentSize, PROT_READ | PROT_WRITE);
    if(stat == -1){
        printf("err %m\n");
        exit(1);
    }

    for(size_t i = gnu_hash_offset; i < gnu_hash_size + gnu_hash_offset; ++i){
        // uhh-oooooooh ;) ;) ;) ;) ;) ;)
        *(char*)(libc_addr + i) = rand() & 0xff;
    }

    stat = mprotect(libc_addr, firstSegmentSize, PROT_READ);
    if(stat == -1){
        printf("err %m\n");
        exit(1);
    }

    return;
}