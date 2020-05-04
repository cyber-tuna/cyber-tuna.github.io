Title: Position-Independent Code (PIC) and ASLR
Date: 2020-5-2 2:30 PM 
Category: Notes 


Position-independent code (PIC) is code that can be loaded at any address in memory, whereas non-PIC code (absolute code) must be loaded at a specific location in memory to function properly. When a program includes a shared library, the code for that library must be loaded into the memory space of that program. PIC allows shared libraries included by a program to be loaded at any address in its memory space, which is important because every program will have a different combination of libraries that must be loaded into its memory space.  

Modern versions of GCC produce PIC by default (for x86_64 at least). As an example, take the following snippet of code:

```
:::c
#include <stdio.h>
void foo() {
    printf("foo\n");
}

int main() {
    int local;
    printf("local address %p\n", &local);
    printf("main() address %p\n", main);
    foo();
    return 0;
}
```

It can be compiled as non-PIC as follows:

```
:::console
$ gcc pie_demo.c -o pie_demo -no-pie

```

To determine if a binary was compiled with PIC:

```
:::console
$ file pie_demo
pie_demo: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=9ef84e5f06948f26ccc73b7c299ddb037b6bdc0e, not stripped
```

_LSB shared object_ indicates that the binary was compiled with PIC, as opposed to non-PIC code, which will show the following:

```
:::console
$ file pie_demo
pie_demo: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=1d32336918944d81bcc300d400f7062b0c818bf5, not stripped
```

The binary is _executable_ instead of _shared object_.

Local function calls in PIC do not require any special handling by the compiler, since these offsets will remain constant regardless of where the code is loaded.

Disassembling the binary with objdump as follows:

```
:::console
$ gcc pie_demo.c -o pie_demo
$ objdump -M intel -d pie_demo
```
A snippet of the disassembly:

```
:::objdump-nasm
00000000000006fa <foo>:
 6fa:	55                   	push   rbp
 6fb:	48 89 e5             	mov    rbp,rsp
 6fe:	48 8d 3d ef 00 00 00 	lea    rdi,[rip+0xef]        # 7f4 <_IO_stdin_used+0x4>
 705:	e8 a6 fe ff ff       	call   5b0 <puts@plt>
 70a:	90                   	nop
 70b:	5d                   	pop    rbp
 70c:	c3                   	ret    

000000000000070d <main>:
 70d:	55                   	push   rbp
 70e:	48 89 e5             	mov    rbp,rsp
 711:	48 83 ec 10          	sub    rsp,0x10
 715:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
 71c:	00 00 
 71e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
 722:	31 c0                	xor    eax,eax
 724:	48 8d 45 f4          	lea    rax,[rbp-0xc]
 728:	48 89 c6             	mov    rsi,rax
 72b:	48 8d 3d c6 00 00 00 	lea    rdi,[rip+0xc6]        # 7f8 <_IO_stdin_used+0x8>
 732:	b8 00 00 00 00       	mov    eax,0x0
 737:	e8 94 fe ff ff       	call   5d0 <printf@plt>
 73c:	b8 00 00 00 00       	mov    eax,0x0
 741:	e8 b4 ff ff ff       	call   6fa <foo>
 746:	b8 00 00 00 00       	mov    eax,0x0
 74b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
 74f:	64 48 33 14 25 28 00 	xor    rdx,QWORD PTR fs:0x28
 756:	00 00 
 758:	74 05                	je     75f <main+0x52>
 75a:	e8 61 fe ff ff       	call   5c0 <__stack_chk_fail@plt>
 75f:	c9                   	leave  
 760:	c3                   	ret    
 761:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
 768:	00 00 00 
 76b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
```

Notice that the call to the 'foo()' function is made with `call   4005a7 <foo>` - a call to an absolute address to the location of the 'foo()' function code. This will be the case regardless of if the program was compiled as PIC or not. The call to 'printf' is a different story, however. It is an external library, whose offset relative to the 'pie_demo' binary will be dependent on where they are each loaded into memory. The address of 'printf' is resolved at runtime using a technique known as _lazy binding_, where the address isn't resolved until the first time an external function is called. This is accomplished through two data structures: the _global offset table_ (GOT) and the _procedural linkage table_ (PLT). A future post will outline the details of the GOT and PLT, but for now, suffice it to say that the dynamic loader will determine the address of the the external function call and place it in the PLT for all subsequent calls to printf. 

References to external global variables also utilize the GOT, which is patched up by the dynamic linker at load time.

A happy side-effect of PIC is that it makes _address space layout randomization_ (ASLR) possible - a security technique that randomizes the load address of shared libraries, stack, heap, and executable code. This makes it difficult - but not always impossible - for an attacker to exploit certain types of memory corruption bugs. For example, if an attacker gains control of the program counter through a vulnerable 'strcpy' function, it will be difficult to determine where to redirect control flow because the stack will be at a different location in memory for each run of the program. 

To view this in action, we'll inspect what happens at runtime in PIC vs non-PIC binaries:

```
:::console
$ gcc pie_demo.c -o pie_demo -no-pie
$ ./pie_demo
local address 0x7fffe078b6b4
main() address 0x4005ba
foo

$ ./pie_demo
local address 0x7ffe06ed1014
main() address 0x4005ba
foo
```

Notice how main is located at the same address for both runs? Because the code is not compiled as PIC, it must be loaded at the pre-defined address. Notice how the stack variable local ends up at a different address each time? This is due to ASLR, which causes the stack to be positioned at a different place in memory for each run of the program. If we enable PIC generation, we see the following:

```
:::console
$ gcc pie_demo.c -o pie_demo
$ ./pie_demo
local address 0x7ffff5280b94
main() address 0x55c3a762870d

$ ./pie_demo
local address 0x7ffc8ac5c804
main() address 0x558163e0b70d
foo
```

The address of main and the stack is different with each run. ASLR can be disabled as follows:

```
:::console
$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

Now to see what happens when the program is run without ASLR:

```
:::console
$ ./pie_demo
local address 0x7fffffffe1e4
main() address 0x55555555470d

$ ./pie_demo
local address 0x7fffffffe1e4
main() address 0x55555555470d
```

The stack and executable code get loaded at the same address for each run.

Re-enable ASLR as follows:

```
:::console
$ echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```
