Title: Linking - Relocations
Date: 2021-2-20 12:00 PM 
Category: Notes

In an effort to fill in some knowledge gaps regarding the linking process for the GNU compiler toolchain, I spent a few minutes exploring the ELF relocation section in a sample binary.

From the ELF man pages, relocation is "the process of connecting symbolic references with symbolic definitions. Relocatable files must have information that describes how to modify their section contents, thus allowing executable and shared object files to hold the right information for a process's program image."

We'll play around with the following code consisting of two separate source files to see how relocations work:

```
:::c
// main.c
#include "hello.h"
#include <stdio.h>

extern char global_variable[];

int main ()
{
  hello("world");
  printf("%s\n", global_variable);
  return 0;
}
```

And the "hello" source and header:
```
:::c
// hello.h
void hello(const char *name);
```

```
:::c
// hello.c
#include <stdio.h>
#include "hello.h"

char global_variable[] = "global var";

void hello(const char *name)
{
    printf("Hello, %s!\n", name);
}
```

Compile the program with the `--save-temps` option; this tells GCC to not delete intermediate files (\*.s, \*.i, \*.o):
```
:::console
$ gcc main.c hello.c -o hello --save-temps
```

Next we'll disassembly the "main.o" object file using objdump:
```
:::objdump-nasm
$ objdump -M intel -d main.o

main.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <main>:
   0:	55                   	push   rbp
   1:	48 89 e5             	mov    rbp,rsp
   4:	48 8d 3d 00 00 00 00 	lea    rdi,[rip+0x0]        # b <main+0xb>
   b:	e8 00 00 00 00       	call   10 <main+0x10>
  10:	48 8d 3d 00 00 00 00 	lea    rdi,[rip+0x0]        # 17 <main+0x17>
  17:	e8 00 00 00 00       	call   1c <main+0x1c>
  1c:	b8 00 00 00 00       	mov    eax,0x0
  21:	5d                   	pop    rbp
  22:	c3                   	ret    
```
Notice the call instruction at address 0xb - this is the "hello()" function call. The previous instruction sets up the first (and only) argument by placing an address into register rdi. The interesting bit here is that both the register load and call instruction use PC relative addressing with an offset of 0x0. This is because the object files have not been merged yet and the address at which the call target will be loaded is not yet known. The assembler generates relocation entries (stored in the .rel.text and .rel.data ELF sections) for each of these references to external code or data for which the final address is unknown.

To view these relocation entries, we can utilize the readelf tool with the -r option.
```
:::console
$ readelf -r main.o

Relocation section '.rela.text' at offset 0x260 contains 4 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000000007  000500000002 R_X86_64_PC32     0000000000000000 .rodata - 4
00000000000c  000b00000004 R_X86_64_PLT32    0000000000000000 hello - 4
000000000013  000c00000002 R_X86_64_PC32     0000000000000000 global_variable - 4
000000000018  000d00000004 R_X86_64_PLT32    0000000000000000 puts - 4

Relocation section '.rela.eh_frame' at offset 0x2c0 contains 1 entry:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000000020  000200000002 R_X86_64_PC32     0000000000000000 .text + 0
```

The first relocation entry at offset 0x13 (the global variable reference) corresponds to the offset in the program at which the linker must fixup with the correct offset once the object files have been merged into an executable.

To see what the linker produces, we'll disassemble the final executable which contains merged code from both source object files:
```
:::objdump-nasm
$ objdump -M intel -d hello

000000000000068a <main>:
 68a:	55                   	push   rbp
 68b:	48 89 e5             	mov    rbp,rsp
 68e:	48 8d 3d cf 00 00 00 	lea    rdi,[rip+0xcf]        # 764 <_IO_stdin_used+0x4>
 695:	e8 13 00 00 00       	call   6ad <hello>
 69a:	48 8d 3d 6f 09 20 00 	lea    rdi,[rip+0x20096f]        # 201010 <global_variable>
 6a1:	e8 aa fe ff ff       	call   550 <puts@plt>
 6a6:	b8 00 00 00 00       	mov    eax,0x0
 6ab:	5d                   	pop    rbp
 6ac:	c3                   	ret    

00000000000006ad <hello>:
 6ad:	55                   	push   rbp
 6ae:	48 89 e5             	mov    rbp,rsp
 6b1:	48 83 ec 10          	sub    rsp,0x10
 6b5:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
 6b9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
 6bd:	48 89 c6             	mov    rsi,rax
 6c0:	48 8d 3d a3 00 00 00 	lea    rdi,[rip+0xa3]        # 76a <_IO_stdin_used+0xa>
 6c7:	b8 00 00 00 00       	mov    eax,0x0
 6cc:	e8 8f fe ff ff       	call   560 <printf@plt>
 6d1:	90                   	nop
 6d2:	c9                   	leave  
 6d3:	c3                   	ret    
 6d4:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
 6db:	00 00 00 
 6de:	66 90                	xchg   ax,ax

```
Both the "main()" function and "hello()" function now exist in the .text section for the executable. Now compare the PC relative code and data accesses to that of the unlinked object files. For example, where instruction that loads `global_variable` was `lea    rdi,[rip+0x0] ` prior to linking, it is now `lea    rdi,[rip+0x20096f]`. To manually verify that the PC-relative reference is correct, we will compute the following in gdb: address of the next instruction (0x6a1) + 0x20096f + load address of 'hello' binary.


```
:::console
dev@ubuntu:~/Documents/linking$ gdb hello
gef➤  b main 
Breakpoint 1 at 0x68e
gef➤  r
Starting program: /home/dev/Documents/linking/hello 
...
Breakpoint 1, 0x000055555555468e in main ()
gef➤  info proc mappings
process 5180
Mapped address spaces:

      Start Addr           End Addr       Size     Offset objfile
      0x555555554000     0x555555555000     0x1000        0x0 /home/dev/Documents/linking/hello
      0x555555754000     0x555555755000     0x1000        0x0 /home/dev/Documents/linking/hello
      0x555555755000     0x555555756000     0x1000     0x1000 /home/dev/Documents/linking/hello
      0x7ffff79e4000     0x7ffff7bcb000   0x1e7000        0x0 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7bcb000     0x7ffff7dcb000   0x200000   0x1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7dcb000     0x7ffff7dcf000     0x4000   0x1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7dcf000     0x7ffff7dd1000     0x2000   0x1eb000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7dd1000     0x7ffff7dd5000     0x4000        0x0 
      0x7ffff7dd5000     0x7ffff7dfc000    0x27000        0x0 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7ffff7fc7000     0x7ffff7fc9000     0x2000        0x0 
      0x7ffff7ff8000     0x7ffff7ffb000     0x3000        0x0 [vvar]
      0x7ffff7ffb000     0x7ffff7ffc000     0x1000        0x0 [vdso]
      0x7ffff7ffc000     0x7ffff7ffd000     0x1000    0x27000 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7ffff7ffd000     0x7ffff7ffe000     0x1000    0x28000 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7ffff7ffe000     0x7ffff7fff000     0x1000        0x0 
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]
  0xffffffffff600000 0xffffffffff601000     0x1000        0x0 [vsyscall]
gef➤  x/s 0x555555554000+0x20096f+0x6a1
0x555555755010 <global_variable>:	"global var"
```

