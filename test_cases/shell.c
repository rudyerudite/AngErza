#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>



void main() {
    char* flag = "lol";
    char* shellcode = (char*) mmap((void*) 0x1337,12, 0, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mprotect(shellcode, 12, PROT_READ | PROT_WRITE | PROT_EXEC);
    printf("stack: %p\n", &shellcode);
        printf("stack: %p\n", *printf);

    fgets(shellcode, 12, stdin);
     
    ((void (*)(char*))shellcode)(flag);
}