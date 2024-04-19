# Memo0

Category: `pwn`

Points: `98`

Solves: 102

Description:

> Mike always forgets important things, so he developed a memo program. Please log in.

---

Honestly this is more of a rev chal than anything.

We start off with a pretty innocent-looking classic pwn menu.

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  int v3; // eax
  unsigned int v5; // [rsp+8h] [rbp-118h]
  char s[264]; // [rsp+10h] [rbp-110h] BYREF
  unsigned __int64 v7; // [rsp+118h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  sub_15B4(a1, a2, a3);
  puts("===================Memo Login===================");
  login();
  v5 = 0;
  while ( 1 )
  {
    while ( 1 )
    {
      v3 = sub_1954();
      if ( v3 != 4 )
        break;
      v5 = 0;
      memset(s, 0, 0x100uLL);
    }
    if ( v3 > 4 )
      break;
    switch ( v3 )
    {
      case 3:
        sub_18BC(s, v5);
        break;
      case 1:
        v5 += sub_184A(s, v5);
        break;
      case 2:
        puts("Content:");
        puts(s);
        break;
      default:
        goto LABEL_12;
    }
  }
LABEL_12:
  puts("Error Choice!");
  return 0LL;
}
```

There seems to be a login function. Indeed, upon running the binary, we are asked to provide a password:

```
$ ./memo0
===================Memo Login===================
Please enter your password:
```

To get past this, we have to look into the login function.

```c
unsigned __int64 login()
{
  size_t v0; // rax
  size_t v1; // rax
  void *s1; // [rsp+8h] [rbp-38h]
  char s[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v5; // [rsp+38h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("Please enter your password: ");
  __isoc99_scanf("%29s", s);
  v0 = strlen(s);
  s1 = (void *)sub_12E9(s, v0);
  if ( !s1 )
  {
    puts("Error!");
    exit(-1);
  }
  v1 = strlen(s2);
  if ( memcmp(s1, s2, v1) )
  {
    puts("Password Error.");
    exit(-1);
  }
  puts("Login Success!");
  sub_1623();
  free(s1);
  return v5 - __readfsqword(0x28u);
}
```

`sub_12E9` seems complicated, we will come back to it later; Interestingly another function is called after we enter the correct password before returning to `main`.

```c
unsigned __int64 sub_1623()
{
  int fd; // [rsp+8h] [rbp-38h]
  __int64 buf[5]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v3; // [rsp+38h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  memset(buf, 0, 32);
  fd = open("./flag", 0);
  if ( fd > 0 && (int)read(fd, buf, 0x20uLL) > 0 )
    puts((const char *)buf);
  return v3 - __readfsqword(0x28u);
}
```

Surprise, we can already get our flag from here! So it seems that we just need to find the correct password to solve this challenge.

Now let us explore `sub_12E9`:

```c
_BYTE *__fastcall sub_12E9(__int64 a1, unsigned __int64 a2)
{
  __int64 v3; // rax
  __int64 v4; // rax
  int v5; // eax
  __int64 v6; // rax
  int v7; // eax
  __int64 v8; // rax
  int i; // [rsp+1Ch] [rbp-34h]
  int v10; // [rsp+20h] [rbp-30h]
  int v11; // [rsp+24h] [rbp-2Ch]
  unsigned int v12; // [rsp+2Ch] [rbp-24h]
  unsigned __int64 v13; // [rsp+30h] [rbp-20h]
  __int64 v14; // [rsp+38h] [rbp-18h]
  unsigned __int64 v15; // [rsp+40h] [rbp-10h]
  _BYTE *v16; // [rsp+48h] [rbp-8h]

  v15 = 4 * ((a2 + 2) / 3);
  v16 = malloc(v15 + 1);
  if ( !v16 )
    return 0LL;
  v13 = 0LL;
  v14 = 0LL;
  while ( v13 < a2 )
  {
    v3 = v13++;
    v10 = *(unsigned __int8 *)(a1 + v3);
    if ( v13 >= a2 )
    {
      v5 = 0;
    }
    else
    {
      v4 = v13++;
      v5 = *(unsigned __int8 *)(a1 + v4);
    }
    v11 = v5;
    if ( v13 >= a2 )
    {
      v7 = 0;
    }
    else
    {
      v6 = v13++;
      v7 = *(unsigned __int8 *)(a1 + v6);
    }
    v12 = (v11 << 8) + (v10 << 16) + v7;
    v16[v14] = aZyxwvutsrqponm[(v12 >> 18) & 0x3F];
    v16[v14 + 1] = aZyxwvutsrqponm[(v12 >> 12) & 0x3F];
    v16[v14 + 2] = aZyxwvutsrqponm[(v12 >> 6) & 0x3F];
    v8 = v14 + 3;
    v14 += 4LL;
    v16[v8] = aZyxwvutsrqponm[v12 & 0x3F];
  }
  for ( i = 0; i < (3 - a2 % 3) % 3; ++i )
    v16[v15 - i - 1] = 61;
  v16[v15] = 0;
  return v16;
}
```

At first glance it seems annoying and complicated. However perhaps it's because I've seen stuff like this quite a few times already, but it should immediately jump out afterwards that we are simply dealing with a base64 function. Some of the "telltale signs" are:

1. `v15 = 4 * ((a2 + 2) / 3);` (Classic 3 bytes -> 4 chars encoding)
2. `v16[v14] = aZyxwvutsrqponm[(v12 >> 18) & 0x3F];` (`& 0x3F` <-> `% 64`, selecting from a key of 64 possible chars)
3. `v16[v15 - i - 1] = 61;` (`61` is ASCII for `=`)

This is simply just base64 with a different charset (`ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/`). Which means our base64-encoded password just has to match with the check string (`s2`).

However, somehow our check string

```
I7HSB6n`B6nevSDa@BL8yC3lB6n`xpX8B6n8Jc<<
```

doesn't seem to be valid base64! To find out more, we set a breakpoint right before `memcmp` in `login` to take a closer look.

```
gef➤  b *0x55555555577a
gef➤  r
...
===================Memo Login===================
Please enter your password: a
...
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555576d <login+170>      lea    rcx, [rip+0x28ac]        # 0x555555558020
   0x555555555774 <login+177>      mov    rsi, rcx
   0x555555555777 <login+180>      mov    rdi, rax
●→ 0x55555555577a <login+183>      call   0x5555555551a0 <memcmp@plt>
   ↳  0x5555555551a0 <memcmp@plt+0>   endbr64
      0x5555555551a4 <memcmp@plt+4>   bnd    jmp QWORD PTR [rip+0x2dfd]        # 0x555555557fa8 <memcmp@got.plt>
      0x5555555551ab <memcmp@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
      0x5555555551b0 <malloc@plt+0>   endbr64
      0x5555555551b4 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2df5]        # 0x555555557fb0 <malloc@got.plt>
      0x5555555551bb <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
memcmp@plt (
   $rdi = 0x005555555592a0 → 0x0000003d3d4a42 ("BJ=="?),
   $rsi = 0x00555555558020 → "J8ITC7oaC7ofwTEbACM9zD4mC7oayqY9C7o9Kd==",
   $rdx = 0x00000000000028,
   $rcx = 0x00555555558020 → "J8ITC7oaC7ofwTEbACM9zD4mC7oayqY9C7o9Kd=="
)
```

Interesting, `s2` has changed somewhere between the start of the program and the login function. (Which is probably why it is placed in an `rw-` segment.) Looking at the xrefs to `s2`, we discover it is referenced in a "secret" function:

```c
size_t sub_1555()
{
  size_t result; // rax
  int i; // [rsp+Ch] [rbp-14h]

  for ( i = 0; ; ++i )
  {
    result = strlen(s2);
    if ( i >= result )
      break;
    ++s2[i];
  }
  return result;
}
```

This function simply increments each byte in the string by 1, which seems to matches up with what we see.

Anyway, dumping the correct check string into cyberchef we get our desired password:

```
CTF_is_interesting_isn0t_it?
```

And entering this password on the server we get our flag!

```
flag{U_r_th3_ma5ter_0f_ba5e64}
```
