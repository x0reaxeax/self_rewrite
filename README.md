# Self rewriting binary (x86)

### I am no expert in x86 assembly, so please keep that in mind when going through this 

## What does this do?
This small C program rewrites its own machine code in memory, in order to alter its execution outcome and.. _(drumroll)_ print a text.
This operation is obviously heavy platform and compiler dependent, so no, it's not convenient, nor portable. Yes, I was bored.

## So how do we do this?
This could be done in a lot of different (and more efficient) ways, but for the sake of my special ed, it does so by executing a few `NOP`s in order to create "empty" memory space that we can "safely" rewrite.  
Plus, what's more exciting than building your own opcode laser beam cannon? Yes, literally anything, but shut up, okay?

First, we're going to write a small program in assembly, that will simply print out some text to `stdout`:
```asm
	push	ebp
	mov	ebp,	esp
	
	mov	eax,	0x04	; sys_write
	mov	ebx,	0x01	; stdout = 1
	mov	ecx,	strout
	mov	edx,	len

	int	0x80		; call kernel
	
	xor	eax,	eax
	xor	ebx,	ebx	; return 0

	mov	eax,	0x1	; sys_exit
	int	0x80		; call kernel
  
	pop	ebp		; boundary pop
```

That will do, let's turn this into a binary, which we can disassemble:
```
└─$ objdump -M intel -d print  

print:     file format elf32-i386


Disassembly of section .text:

08048080 <_entry>:
 8048080:       55                      push   ebp
 8048081:       89 e5                   mov    ebp,esp
 8048083:       b8 04 00 00 00          mov    eax,0x4
 8048088:       bb 01 00 00 00          mov    ebx,0x1
 804808d:       b9 a8 90 04 08          mov    ecx,0x80490a8
 8048092:       ba 07 00 00 00          mov    edx,0x7
 8048097:       cd 80                   int    0x80
 8048099:       31 c0                   xor    eax,eax
 804809b:       31 db                   xor    ebx,ebx
 804809d:       b8 01 00 00 00          mov    eax,0x1
 80480a2:       cd 80                   int    0x80
 80480a4:       5d                      pop    ebp
```

Alright, we can ignore the epilogue and jump directly to `0x8048083`:
```asm
8048083:       b8 04 00 00 00          mov    eax, 0x4
```

That's nice! But what can we do with this?

Well, we're gonna take the opcodes from this disassembly and rewrite our `NOP`s with them. Let's go!

First, we're gonna need to calculate how many `NOP`s we need to be able to fit all that junk in:  
We can either count the opcode bytes manually like turds, or we can just substract the start address from the end address and add 1 to get the result:  
```(0xa4 - 0x83) + 0x1 = 0x22 (34d)```   

Nice! Let's place our `NOP`s into our program!
```c
int main(void) {
  
  __asm volatile ("nop");
  /*
   ...
   ...
  */
  __asm volatile ("nop");
  
  /* our text to print | 0xa = newline ; 0x0 = nullterm */
  volatile unsigned char stdout_buffer[7] = { 'p', 'w', 'n', 'e', 'd', 0xa, 0x0 };

  return 0;
}
```

In order to rewrite our nops, we have to know the offset from `main()` to the first `NOP` in memory.  
If we compile our code and look at the disassembly, we can easily grab the offset from there:
```asm
000012a7 <main>:
 => 12a7:       8d 4c 24 04             lea    ecx,[esp+0x4]
    12ab:       83 e4 f0                and    esp,0xfffffff0
    12ae:       ff 71 fc                push   DWORD PTR [ecx-0x4]
    12b1:       55                      push   ebp
    12b2:       89 e5                   mov    ebp,esp
    12b4:       53                      push   ebx
    12b5:       51                      push   ecx
    12b6:       83 ec 60                sub    esp,0x60
    12b9:       e8 12 fe ff ff          call   10d0 <__x86.get_pc_thunk.bx>
    12be:       81 c3 42 2d 00 00       add    ebx,0x2d42
 => 12c4:       90                      nop
    12c5:       90                      nop
    12c6:       90                      nop
    ...
    ...
```
`0xc4 - 0xa7 = 0x1D`
So `<main> + 0x1D` is our starting address.

We're going to quickly scan our `NOP`s to check if we have all the space we need and also the correct offset. Let's build a small function for that:

```c
unsigned char print_opcode(unsigned char *byte) {
  printf("[%p] opcode: 0x%2x\n", byte, *byte);
	return *byte;
}
```

And the actual check:

```c
int main(void) {
  /* ... */
  
  unsigned char (*mainptr)() = main;
  unsigned char *opc_ptr = mainptr + OPCODE_INDENT;
  
  /* verify nops */
  for (int i = 0; i < (0x16 + 0xc); i++) {
    if (print_opcode(opc_ptr) != 0x90) {
      fprintf(stderr, "not all nops could be verified!\n");
      return 1;
    }
    opc_ptr++;
  }

  
  volatile unsigned char stdout_buffer[] = { 'p', 'w', 'n', 'e', 'd', 0xa, 0 };
  
  /* ... */
}
```

Great, now we're gonna grab the opcodes from our little assembly program and put them into a C array:
```c
unsigned char machine_code[] = { 0xb8, 0x04, 0x00, 0x00, 0x00, 0xbb, 0x01, 0x00, 0x00, 0x00, 0xb9, 0xa8, 0x90, 0x04, 0x08, 0xba, 0x07, 0x00, 0x00, 0x00, 0xcd, 0x80, /* sys_exit */ 0x31, 0xc0, 0x31, 0xdb, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xcd, 0x80, 0x5d };
```

This needs a little tweaking:

We need to change the address `0x80490a8` to our `stdout_buffer[7]`
```asm
 804808d:       b9 a8 90 04 08          mov    ecx,0x80490a8
```

Since we don't know this address now, we'll need to grab it from memory at runtime:
```c
  /* ... */
 
  /* get stdout_buffer addy */
  
  unsigned char addy[4];
  unsigned char *buf_ptr = stdout_buffer;
  unsigned char *addy_ptr = (unsigned char *)&buf_ptr;
    
  for (int i = 0; i < 4; i++) {
    addy[i] = addy_ptr[i];
  }
```

Now we're ready to build our opcode laser beam cannon and call `main()`:
```c
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
  
  /* call main */
  main();
  
  return 0;
```

Let's glue all this together and:
```
$ gcc -ggdb -o x32bin self_rewrite.c
$ ./x32bin
[0x5664c2c4] opcode: 0x90
[0x5664c2c5] opcode: 0x90
[0x5664c2c6] opcode: 0x90
[0x5664c2c7] opcode: 0x90
[0x5664c2c8] opcode: 0x90
[0x5664c2c9] opcode: 0x90
[0x5664c2ca] opcode: 0x90
[0x5664c2cb] opcode: 0x90
[0x5664c2cc] opcode: 0x90
[0x5664c2cd] opcode: 0x90
[0x5664c2ce] opcode: 0x90
[0x5664c2cf] opcode: 0x90
[0x5664c2d0] opcode: 0x90
[0x5664c2d1] opcode: 0x90
[0x5664c2d2] opcode: 0x90
[0x5664c2d3] opcode: 0x90
[0x5664c2d4] opcode: 0x90
[0x5664c2d5] opcode: 0x90
[0x5664c2d6] opcode: 0x90
[0x5664c2d7] opcode: 0x90
[0x5664c2d8] opcode: 0x90
[0x5664c2d9] opcode: 0x90
[0x5664c2da] opcode: 0x90
[0x5664c2db] opcode: 0x90
[0x5664c2dc] opcode: 0x90
[0x5664c2dd] opcode: 0x90
[0x5664c2de] opcode: 0x90
[0x5664c2df] opcode: 0x90
[0x5664c2e0] opcode: 0x90
[0x5664c2e1] opcode: 0x90
[0x5664c2e2] opcode: 0x90
[0x5664c2e3] opcode: 0x90
[0x5664c2e4] opcode: 0x90
[0x5664c2e5] opcode: 0x90
Segmentation Fault
``` 

Oopsie! We hit access violation while trying to rewrite our `NOP`s in memory. If we run `objdump -x` with our executable, we can see that the text segment which contains our code is marked as `READONLY`:
```asm
13 .text         00000455  00001090  00001090  00001090  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
```

We can however "unlock" the text segment with [mprotect()](https://man7.org/linux/man-pages/man2/mprotect.2.html).  
The manual page for `mprotect()` states the following:
```
       mprotect() changes the access protections for the calling
       process's memory pages containing any part of the address range
       in the interval [addr, addr+len-1].  addr must be aligned to a
       page boundary.
```
"addr must be aligned to a page boundary"?
Alright, quick googling led me to [getpagesize()](https://man7.org/linux/man-pages/man2/getpagesize.2.html) and [Writing a Self-Mutating x86_64 C Program](https://shanetully.com/2013/12/writing-a-self-mutating-x86_64-c-program/) (<- take a look at this, amazing info!)

```c
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
```
Alright, let's put all this together once again and execute:
```
└─$ ./x32xbin                 
[0x5664c2c4] opcode: 0x90
[0x5664c2c5] opcode: 0x90
[0x5664c2c6] opcode: 0x90
[0x5664c2c7] opcode: 0x90
[0x5664c2c8] opcode: 0x90
[0x5664c2c9] opcode: 0x90
[0x5664c2ca] opcode: 0x90
[0x5664c2cb] opcode: 0x90
[0x5664c2cc] opcode: 0x90
[0x5664c2cd] opcode: 0x90
[0x5664c2ce] opcode: 0x90
[0x5664c2cf] opcode: 0x90
[0x5664c2d0] opcode: 0x90
[0x5664c2d1] opcode: 0x90
[0x5664c2d2] opcode: 0x90
[0x5664c2d3] opcode: 0x90
[0x5664c2d4] opcode: 0x90
[0x5664c2d5] opcode: 0x90
[0x5664c2d6] opcode: 0x90
[0x5664c2d7] opcode: 0x90
[0x5664c2d8] opcode: 0x90
[0x5664c2d9] opcode: 0x90
[0x5664c2da] opcode: 0x90
[0x5664c2db] opcode: 0x90
[0x5664c2dc] opcode: 0x90
[0x5664c2dd] opcode: 0x90
[0x5664c2de] opcode: 0x90
[0x5664c2df] opcode: 0x90
[0x5664c2e0] opcode: 0x90
[0x5664c2e1] opcode: 0x90
[0x5664c2e2] opcode: 0x90
[0x5664c2e3] opcode: 0x90
[0x5664c2e4] opcode: 0x90
[0x5664c2e5] opcode: 0x90
[mprotect] setting rw on 5664c000 | sz: 4096
[mprotect] rw set!
pwned
```

Wooohoo, it worked! Let's take a closer look at the disassembly in gdb:

Quick peek at our `NOP`s:
```asm
Dump of assembler code for function main:                                                                              
   0x565562a7 <+0>:     8d 4c 24 04     lea    ecx,[esp+0x4]                                                           
   0x565562ab <+4>:     83 e4 f0        and    esp,0xfffffff0                                                          
   0x565562ae <+7>:     ff 71 fc        push   DWORD PTR [ecx-0x4]                                                     
   0x565562b1 <+10>:    55      push   ebp                                                                             
   0x565562b2 <+11>:    89 e5   mov    ebp,esp                                                                         
   0x565562b4 <+13>:    53      push   ebx                                                                             
   0x565562b5 <+14>:    51      push   ecx                                                                             
   0x565562b6 <+15>:    83 ec 60        sub    esp,0x60                                                                
   0x565562b9 <+18>:    e8 12 fe ff ff  call   0x565560d0 <__x86.get_pc_thunk.bx>                                      
   0x565562be <+23>:    81 c3 42 2d 00 00       add    ebx,0x2d42                                                      
=> 0x565562c4 <+29>:    90      nop                                                                                    
   0x565562c5 <+30>:    90      nop                                                                                    
   0x565562c6 <+31>:    90      nop                                                                                    
   0x565562c7 <+32>:    90      nop                                                                                    
   0x565562c8 <+33>:    90      nop
   0x565562c9 <+34>:    90      nop
   0x565562ca <+35>:    90      nop
   0x565562cb <+36>:    90      nop
   0x565562cc <+37>:    90      nop
   0x565562cd <+38>:    90      nop
   0x565562ce <+39>:    90      nop
   0x565562cf <+40>:    90      nop
   0x565562d0 <+41>:    90      nop
   0x565562d1 <+42>:    90      nop
   0x565562d2 <+43>:    90      nop
   0x565562d3 <+44>:    90      nop
   0x565562d4 <+45>:    90      nop
   0x565562d5 <+46>:    90      nop
   0x565562d6 <+47>:    90      nop
   0x565562d7 <+48>:    90      nop
   0x565562d8 <+49>:    90      nop
   0x565562d9 <+50>:    90      nop
   0x565562da <+51>:    90      nop
   0x565562db <+52>:    90      nop
   0x565562dc <+53>:    90      nop
   0x565562dd <+54>:    90      nop
   0x565562de <+55>:    90      nop
   0x565562df <+56>:    90      nop
   0x565562e0 <+57>:    90      nop
   0x565562e1 <+58>:    90      nop
   0x565562e2 <+59>:    90      nop
   0x565562e3 <+60>:    90      nop
   0x565562e4 <+61>:    90      nop
   0x565562e5 <+62>:    90      nop
   0x565562e6 <+63>:    8d 83 a7 d2 ff ff       lea    eax,[ebx-0x2d59]
   ...
```
  
  ..and after rewriting the machine code:
  
  ```asm
  Dump of assembler code for function main:
    0x565562a7 <+0>:     8d 4c 24 04     lea    ecx,[esp+0x4]
    0x565562ab <+4>:     83 e4 f0        and    esp,0xfffffff0
    0x565562ae <+7>:     ff 71 fc        push   DWORD PTR [ecx-0x4]
    0x565562b1 <+10>:    55      push   ebp
    0x565562b2 <+11>:    89 e5   mov    ebp,esp
    0x565562b4 <+13>:    53      push   ebx
    0x565562b5 <+14>:    51      push   ecx
    0x565562b6 <+15>:    83 ec 60        sub    esp,0x60
    0x565562b9 <+18>:    e8 12 fe ff ff  call   0x565560d0 <__x86.get_pc_thunk.bx>
    0x565562be <+23>:    81 c3 42 2d 00 00       add    ebx,0x2d42
  =>0x565562c4 <+29>:    b8 04 00 00 00  mov    eax,0x4
    0x565562c9 <+34>:    bb 01 00 00 00  mov    ebx,0x1
    0x565562ce <+39>:    b9 b7 d0 ff ff  mov    ecx,0xffffd0b7
    0x565562d3 <+44>:    ba 07 00 00 00  mov    edx,0x7
    0x565562d8 <+49>:    cd 80   int    0x80
    0x565562da <+51>:    31 c0   xor    eax,eax
    0x565562dc <+53>:    31 db   xor    ebx,ebx
    0x565562de <+55>:    b8 01 00 00 00  mov    eax,0x1
    0x565562e3 <+60>:    cd 80   int    0x80
    0x565562e5 <+62>:    5d      pop    ebp
    0x565562e6 <+63>:    8d 83 a7 d2 ff ff       lea    eax,[ebx-0x2d59]
    ...
```

Yaaaaay, we printed some text, and it only tooks us `UINT_MAX` hours!!! Can you even remotely believe that?  
Yeesh.

