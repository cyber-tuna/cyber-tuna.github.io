Title: Pwnable.tw Start Writeup 
Date: 2020-5-5 2:30 PM 
Category: CTF 

The first step is to download the binary:

```
:::console
$ wget https://pwnable.tw/static/chall/start
```

As usual, the first step is to 'file' the binary:

```
:::console
$ file start
start: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, not stripped
```

First off, note that the binary is 32-bit and was not compiled with -fPIC. Next let's disassemble:

```
:::objdump-nasm
$ objdump -M intel -d start

start:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:	54                   	push   esp
 8048061:	68 9d 80 04 08       	push   0x804809d
 8048066:	31 c0                	xor    eax,eax
 8048068:	31 db                	xor    ebx,ebx
 804806a:	31 c9                	xor    ecx,ecx
 804806c:	31 d2                	xor    edx,edx
 804806e:	68 43 54 46 3a       	push   0x3a465443
 8048073:	68 74 68 65 20       	push   0x20656874
 8048078:	68 61 72 74 20       	push   0x20747261
 804807d:	68 73 20 73 74       	push   0x74732073
 8048082:	68 4c 65 74 27       	push   0x2774654c
 8048087:	89 e1                	mov    ecx,esp
 8048089:	b2 14                	mov    dl,0x14
 804808b:	b3 01                	mov    bl,0x1
 804808d:	b0 04                	mov    al,0x4
 804808f:	cd 80                	int    0x80
 8048091:	31 db                	xor    ebx,ebx
 8048093:	b2 3c                	mov    dl,0x3c
 8048095:	b0 03                	mov    al,0x3
 8048097:	cd 80                	int    0x80
 8048099:	83 c4 14             	add    esp,0x14
 804809c:	c3                   	ret

0804809d <_exit>:
 804809d:	5c                   	pop    esp
 804809e:	31 c0                	xor    eax,eax
 80480a0:	40                   	inc    eax
 80480a1:	cd 80                	int    0x80
```

Notice the 'int 0x80' instructions - this is an "interupt" instruction that will cause any of the 256 entries in the IA32 exception table to run. In this case, "int 0x80" causes the exception handler 0x80 (decimal 128) to run, which is responsible for handling system calls. The system call to execute is controlled by placing the system call number in register eax. The system call table on my machine is located at /usr/include/asm/unistd_32.h:

```
:::c
ifndef _ASM_X86_UNISTD_32_H
#define _ASM_X86_UNISTD_32_H 1

#define __NR_restart_syscall 0
#define __NR_exit 1
#define __NR_fork 2
#define __NR_read 3
#define __NR_write 4
#define __NR_open 5
```

Our target binary moves the value 0x4 into register 'al' - the lower 8 bits of eax - just prior to the `int 0x80` instruction. Consulting the table above, we see that this corresponds to the 'write' system call. From the man pages, we see:

```
:::console
$ man 2 write

WRITE(2)                                                               Linux Programmer's Manual                                                               WRITE(2)

NAME
       write - write to a file descriptor

SYNOPSIS
       #include <unistd.h>

       ssize_t write(int fd, const void *buf, size_t count);
```

The write system call takes three arguments. Instead of passing parameters on the stack (as happens with function calls in IA32), they are passed via general purpose registers. The syscall number is placed in eax, and arguments are placed in ebx, ecx, edx, esi, edi, and ebp - up to six arbitrary arguments. With that, we know that the fd (file descriptor) argument will be placed in ebx, the buffer 'buf' (the data to be written to the file descriptor) into ecx, and finally 'count' (the number of bytes to be written) to the file descriptor.

A C representation of the system call might look as follows:
```
:::c
write(1, sp, 0x14);
```

Where 1 represents the standard output file descriptor, kp is the pointer to the top of the stack, and 0x14 (or 20 in decimal) bytes to be written. I used binary ninja to decode the data being pushed on to the stack just prior to the call to write as characters:

![image info]({static}/images/start.png)

Great! The characters 'Let's start the CTF:' are pushed on to the stack and will get written to standard output, which in this case will be our terminal.




first check NX bit with checksec GEF command. NX is disabled. a

gef➤  r <<< $(python -c 'print "\x61"*20 + "\x87\x80\x04\x08"')
