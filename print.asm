section .data
	strout	db	"tststr", 0xa
	len	equ	$ - strout

global _entry

section .text

_entry:
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
