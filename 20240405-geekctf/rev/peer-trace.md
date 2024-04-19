# Peer-Trace

Category: `rev`

Points: `289`

Solves: 28

Description:

> P..trace?

---

The name pretty much tells us that this challenge plays with two binaries where one controls (and discreetly modifies) the other via `ptrace`. And cracking the binaries open confirms the guess.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
//   ...
  v25[7] = __readfsqword(0x28u);
  v8 = fork();
  if ( !v8 )
  {
    ptrace(PTRACE_TRACEME, 0LL, 0LL, 0LL);
    execl("puppet", "puppet", 0LL);
  }
  wait((__WAIT_STATUS)&stat_loc);
  if ( ((__int64)stat_loc.__uptr & 0x7F) == 0 )
    return 0;
//   ...
}
```

We take a look at the `puppet`:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+4h] [rbp-5Ch]
  ssize_t v5; // [rsp+8h] [rbp-58h]
  char buf[72]; // [rsp+10h] [rbp-50h] BYREF
  unsigned __int64 v7; // [rsp+58h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  puts("I'm a flag checker, give me your flag and I'll check it for you. ");
  printf("Input your flag here: ");
  fflush(stdout);
  v5 = read(0, buf, 0x30uLL);
  if ( v5 <= 0 )
    puts("No flag to check. Good byte~");
  if ( v5 != 48 )
    puts("Flag length mismatch.");
  for ( i = 0; v5 > i; ++i )
    buf[i] ^= 0x28u;
  if ( !memcmp(buf, &ct, 0x30uLL) )
    puts("Passed");
  else
    puts("Invalid");
  return 0;
}
```

Pretty innocent-looking. But of course the stored data is a jumbled mess and working out the flag statically doesn't work. Dynamic analysis is also difficult due to `ptrace`.

---

## Part I

Going back to the main binary:

```c
  ptrace(PTRACE_SYSCALL, v8, 0LL, 0LL);
  HIDWORD(stat_loc.__iptr) = 0;
  v10 = 0LL;
  while ( 1 )
  {
    wait((__WAIT_STATUS)&stat_loc);
    if ( ((__int64)stat_loc.__uptr & 0x7F) == 0 )
      break;
    if ( !ptrace(PTRACE_PEEKUSER, v8, 120LL, 0LL) )
    {
      ptrace(PTRACE_GETREGS, v8, 0LL, v20);
      if ( HIDWORD(stat_loc.__iptr) )
      {
        if ( v10 && v22 )
        {
          v12 = 8 * ((v22 >> 3) + 1);
          for ( i = 0; (__int64)(v12 + 6) >= i; i += 8 )
          {
            v4 = ptrace(PTRACE_PEEKDATA, v8, v10 + i, 0LL);
            v25[0] = v4;
            v13 = (unsigned __int8)v4;
            LOBYTE(v25[0]) = BYTE5(v4);
            BYTE5(v25[0]) = v4;
            v14 = BYTE1(v4);
            BYTE1(v25[0]) = HIBYTE(v4);
            HIBYTE(v25[0]) = BYTE1(v4);
            v15 = BYTE2(v4);
            BYTE2(v25[0]) = BYTE6(v4);
            BYTE6(v25[0]) = BYTE2(v4);
            for ( j = 0; i + j < v22 && j <= 7; ++j )
              *((_BYTE *)v25 + j) -= j + i;
            v16 = BYTE3(v25[0]);
            BYTE3(v25[0]) = BYTE4(v25[0]);
            BYTE4(v25[0]) = v16;
            ptrace(PTRACE_POKEDATA, v8, i + v10, v25[0]);
          }
          v10 = 0LL;
          break;
        }
        HIDWORD(stat_loc.__iptr) = 0;
      }
      else
      {
        HIDWORD(stat_loc.__iptr) = 1;
        if ( !v24 )
          v10 = v23;
      }
    }
    ptrace(PTRACE_SYSCALL, v8, 0LL, 0LL);
  }
```

Notice the `break` after the `for`-loop. This means that the `for`-loop is only accessed once. We can set a breakpoint right before that chunk of code (right after the `if` above) to see where and how it is accessed.

But before that, let's work out the memory layout.

```
      ptrace(PTRACE_GETREGS, v8, 0LL, v20);
```

stores the register information in `v20`, which looks like

```c
  char v20[32]; // [rsp+70h] [rbp-120h] BYREF
  __int64 v21; // [rsp+90h] [rbp-100h]
  unsigned __int64 v22; // [rsp+C0h] [rbp-D0h]
  __int64 v23; // [rsp+D8h] [rbp-B8h]
  __int64 v24; // [rsp+E0h] [rbp-B0h]
  __int64 v25[8]; // [rsp+150h] [rbp-40h]
```

Note that the registers struct obviously has to be way larger than 32 bytes, which overflows into the subsequent variables.

```c
struct user_regs_struct
{
  __extension__ unsigned long long int r15;
  __extension__ unsigned long long int r14;
  __extension__ unsigned long long int r13;
  __extension__ unsigned long long int r12;
  __extension__ unsigned long long int rbp;
  __extension__ unsigned long long int rbx;
  __extension__ unsigned long long int r11;
  __extension__ unsigned long long int r10;
  __extension__ unsigned long long int r9;
  __extension__ unsigned long long int r8;
  __extension__ unsigned long long int rax;
  __extension__ unsigned long long int rcx;
  __extension__ unsigned long long int rdx;
  __extension__ unsigned long long int rsi;
  __extension__ unsigned long long int rdi;
  __extension__ unsigned long long int orig_rax;
  __extension__ unsigned long long int rip;
  __extension__ unsigned long long int cs;
  __extension__ unsigned long long int eflags;
  __extension__ unsigned long long int rsp;
  __extension__ unsigned long long int ss;
  __extension__ unsigned long long int fs_base;
  __extension__ unsigned long long int gs_base;
  __extension__ unsigned long long int ds;
  __extension__ unsigned long long int es;
  __extension__ unsigned long long int fs;
  __extension__ unsigned long long int gs;
};
```

With the struct information as well as the offset provided by the decompilation we can figure out that `v22`, `v23` and `v24` corresponds to `rax`, `rsi` and `rdi` respectively. In this case the `puppet` stopped after the `read` syscall, with `rdi`, `rsi` and `rdi` being `stdin`, buffer address and number of bytes read respectively.

Hence we can interpret it as that the something similar to the code below is "inserted" after the `read`:

```python
for i in range(0, len(BUF), 8):
    cur = BUF[i:i+8]
    BUF[i:i+8] = [
        cur[5]-(i+0),
        cur[7]-(i+1),
        cur[6]-(i+2),
        cur[4]-(i+4),
        cur[3]-(i+3),
        cur[0]-(i+5),
        cur[2]-(i+6),
        cur[1]-(i+7),
    ]
```

---

## Part II

After this, we get to our second tampering.

```c
  v9 = 0;
  v25[0] = 0xA39C3E6994313F40LL;
  v25[1] = 0x17872470565B9B60LL;
  v25[2] = 0x11A918AABA97CA68LL;
  v25[3] = 0xB8F1B0AB9B3DD3B0LL;
  v25[4] = 0x488749FB6A1835E4LL;
  v25[5] = 0x82926F78FE98158LL;
  while ( 1 )
  {
    wait((__WAIT_STATUS)&stat_loc);
    if ( ((__int64)stat_loc.__uptr & 0x7F) == 0 )
      break;
    v17 = ptrace(PTRACE_PEEKUSER, v8, 128LL, 0LL);
    v18 = ptrace(PTRACE_PEEKDATA, v8, v17, 0LL);
    if ( (v17 & 0xFFF) == 658 && (v18 & 0xFFFFFFFFFFLL) == 0xA4458BC289LL )
    {
      ptrace(PTRACE_GETREGS, v8, 0LL, v20);
      v19 = (unsigned int)ptrace(PTRACE_PEEKDATA, v8, v21 - 92, 0LL);
      v22 = (unsigned int)v22 + (unsigned __int64)*((unsigned __int8 *)v25 + v19);
      ptrace(PTRACE_SETREGS, v8, 0LL, v20);
      v9 = 1;
    }
    ptrace(PTRACE_SINGLESTEP, v8, 0LL, 0LL);
  }
```

We can see that the modification (`PTRACE_SETREGS`) triggers when `rip` (`regs_struct[128]`) ends in `0x292` (658) and the code at `[rip]` is `89 C2 8B 45 A4`. We can easily verify that this corresponds to address `0x1292` in `puppet`, right after the `xor` instruction. As mentioned above, `v22` corresponds to `rax`, which is modified before passing back to the `peek` process. In the context of `puppet` it looks like this:

```c
  for ( i = 0; v5 > i; ++i )
    buf[i] ^= 0x28u;
```

```asm
1285    mov     eax, [rbp+var_5C]
1288    cdqe
128A    movzx   eax, [rbp+rax+buf]
128F    xor     eax, 28h
1292    mov     edx, eax
1294    mov     eax, [rbp+var_5C]
1297    cdqe
1299    mov     [rbp+rax+buf], dl
129D    add     [rbp+var_5C], 1
```

Meanwhile, `v21` corresponds to `rbp`, which means that `[v21 - 92]` stores the current index of the loop in `puppet` (since 92 is `0x5c`). In code it looks like this, "inserted" after the `xor` operations:

```python
import struct

KEY = b''.join(struct.pack('Q', x) for x in [0xA39C3E6994313F40, 0x17872470565B9B60, 0x11A918AABA97CA68, 0xB8F1B0AB9B3DD3B0, 0x488749FB6A1835E4, 0x82926F78FE98158])

BUF = [(x+y)%256 for x, y in zip(BUF, KEY)]
```

---

## Part III

With this, we simply have to reverse everything above.

```python
import struct

END = bytes([0x9C, 0x56, 0x89, 0xF3, 0xB5, 0x87, 0x0F, 0xF0, 0xD1, 0x9B, 0x6C, 0xA4, 0xD1, 0xA2, 0x0, 0x35, 0x81, 0xD4, 0xB0, 0x30, 0xF3, 0x89, 0x0A, 0x89, 0x13, 0x45, 0xA0, 0x8, 0xCA, 0x1F, 0x0F, 0x20, 0x0, 0x4F, 0x56, 0x81, 0x3, 0x5B, 0xAB, 0xC3, 0xC7, 0xFD, 0x57, 0xBB, 0x9, 0x3B, 0x95, 0x8])

KEY = b''.join(struct.pack('Q', x) for x in [0xA39C3E6994313F40, 0x17872470565B9B60, 0x11A918AABA97CA68, 0xB8F1B0AB9B3DD3B0, 0x488749FB6A1835E4, 0x82926F78FE98158])

a = [(((x-y)%256)^0x28)+i for i, (x, y) in enumerate(zip(END, KEY))]
c = ''.join(bytes([b[5], b[7], b[6], b[4]-1, b[3]+1, b[0], b[2], b[1]]).decode() for i in range(0, len(a), 8) if (b := a[i:i+8]))
print(c)
```

```
flag{tr@cE_TraC1ng_trAC3d_TRaces_z2CcT8SjWre0op}
```
