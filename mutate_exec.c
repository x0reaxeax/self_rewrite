#include <stdio.h>

#include <unistd.h>         /* getpagesize() */
#include <sys/mman.h>       /* mprotect() */

int unlock_text_segment(unsigned char *addr) {
	int pagesz = getpagesize();
	addr -= (unsigned long) addr % pagesz;

	printf("[mprotect] setting rw on %lx | sz: %d\n", (unsigned long)addr, pagesz);

	int chmem = mprotect(addr, pagesz, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (chmem != 0) {
		fprintf(stderr, "[e%d] failed to set rwx on text segment\n", chmem);
		return chmem;
	}
}

unsigned char print_opcode(unsigned char *byte) {
	printf("[%p] opcode: 0x%2x\n", byte, *byte);
	return *byte;
}

#define OPCODE_INDENT	0x1d

int main(void) {
	/* we need 0x16 (22) bytes to print shit out */

    /*
     *  mov eax, 0x4        ; sys_write
     *  mov ebx, 0x1        ; stdout == 1
     *  mov ecx, 0xdeadbeef ; buffer addy
     *  mov edx, 0x7        ; strlen
     *
     *  int 0x80            ; call kernel
     *
    */

	__asm volatile ("nop");	
	__asm volatile ("nop");
	__asm volatile ("nop");
	__asm volatile ("nop");
	__asm volatile ("nop");
	__asm volatile ("nop");
	__asm volatile ("nop");
	__asm volatile ("nop");
	__asm volatile ("nop");
	__asm volatile ("nop");
	__asm volatile ("nop");
	__asm volatile ("nop");
	__asm volatile ("nop");
	__asm volatile ("nop");
	__asm volatile ("nop");
	__asm volatile ("nop");
	__asm volatile ("nop");
	__asm volatile ("nop");
	__asm volatile ("nop");
	__asm volatile ("nop");
	__asm volatile ("nop");
	__asm volatile ("nop");

    /* call sys_exit - we need another  0xc / 12d bytes */

    /*
     *  xor eax, eax    ; return 0
     *  xor ebx, ebx    ; get rid of ebx
     *
     *  mov eax, 0x1    ; sys_exit
     *
     *  int 0x80        ; call kernel
     *
     *  pop ebp         ; useless pop
    */


    __asm volatile ("nop"); // 31   xor
    __asm volatile ("nop"); // c0   eax, eax
    __asm volatile ("nop"); // 31   xor
    __asm volatile ("nop"); // db   ebx, ebx
    __asm volatile ("nop"); // b8   mov eax
    __asm volatile ("nop"); // 01   0x1
    __asm volatile ("nop"); // 00
    __asm volatile ("nop"); // 00
    __asm volatile ("nop"); // 00
    __asm volatile ("nop"); // cd   int
    __asm volatile ("nop"); // 80   0x80
    __asm volatile ("nop"); // 5d   pop ebp ; this doesnt get executed, I used it as sort of a boundary while debugging

    unsigned char (*mainptr)() = main;
    unsigned char *opc_ptr = mainptr + OPCODE_INDENT;

    /* verify nops */
    for (int i = 0; i < (0x16 + 0xc); i++) {
	if (print_opcode(opc_ptr) != 0x90) {
		printf("not all nops could be verified!\n");
		return 1;
	}
	opc_ptr++;
    }

    /* restore position */
    opc_ptr = mainptr + OPCODE_INDENT;

    int rwret = unlock_text_segment(main);
    if (rwret != 0) { 
	fprintf(stderr, "[E%d] Failed to get rwx on text segment\n", rwret);	
	return 1;
    }

    printf("[mprotect] rw set!\n");

    unsigned char machine_code[] = { 0xb8, 0x04, 0x00, 0x00, 0x00, 0xbb, 0x01, 0x00, 0x00, 0x00, 0xb9, 0xa8, 0x90, 0x04, 0x08, 0xba, 0x07, 0x00, 0x00, 0x00, 0xcd, 0x80, /* sys_exit */ 0x31, 0xc0, 0x31, 0xdb, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xcd, 0x80, 0x5d };

    /* get stdout_buffer addy */
    volatile unsigned char stdout_buffer[] = { 'p', 'w', 'n', 'e', 'd', 0xa, 0 };
    unsigned char addy[4];
    unsigned char *mca_ptr = stdout_buffer;
    unsigned char *addy_ptr = (unsigned char *)&mca_ptr;

    for (int i = 0; i < 4; i++) {
        addy[i] = addy_ptr[i];
    }

    /* rewrite opcodes */
    for (int i = 0; i < (0x16 + 0xc); i++) {
        if (i == 11) {
            /* rewrite addy */
            for (int j = 0; j < 4; j++) {    
                *opc_ptr = addy[j];
                opc_ptr++;
            }
            i = i + 3; 
        } else {
            *opc_ptr = machine_code[i];
            opc_ptr++;
        }   
    }
	
    /* jump back to main */
    main();

    return 0;
}
