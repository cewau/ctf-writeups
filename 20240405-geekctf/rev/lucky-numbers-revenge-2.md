# lucky numbers revenge 2

Category: `rev`

Points: `785`

Solves: 4

---

## Part I

The main function in the binary provided is almost identical to the that for the [previous challenge](lucky-numbers.md), except for an additional check:

```asm
; same as lucky numbers, see writeup
mov     rax, [rsp+198h+var_110]
mov     [rsp+198h+var_78], rax
; added check
xor     al, bpl
jz      loc_981F
```

Tracing back, we see that `rbp` has the same function as `rax` except it holds the 1st number. This means that this check essentially ensures that the first byte of the 2 numbers must be different from each other.

But then how are we supposed to break the hash? Are we expected to find a collision?

No. The secret lies in the out-of-place `trim_matches` right above the 2 `Hasher.write` calls for the 1st number.

If you recall from the previous challenge, `rsi` (which is `mov`ed from `rax`) and `rdx` seem to be populated automatically before the first `Hasher.write` is called. Well, they actually are results from the `trim_matches` function, where `rax` is the string address and `rdx` is the length of the string. Basically the u64 number (1st number) is treated as a string of 8 bytes and passed into `trim_matches`.

But what is `trim_matches`? Does it not just trim trailing whitespaces? Well, if you stare closely, there are actually 2 functions named `trim_matches`:

```
_ZN4core3str21_$LT$impl$u20$str$GT$12trim_matches17hb3529f68d9fac40bE
```

```
_ZN4core3str21_$LT$impl$u20$str$GT$12trim_matches17hb17aa2e5150f772eE
```

The former (found everywhere else) is our good-old-fashioned trim, while the latter (found only right before the `Hasher.write` calls)... I don't know. Let's explore.

---

## Part II

We look at the head and tail blocks first:

```asm
; core::str::_$LT$impl$u20$str$GT$::trim_matches::hb17aa2e5150f772e
_ZN4core3str21_$LT$impl$u20$str$GT$12trim_matches17hb17aa2e5150f772eE proc near
; __unwind {
push    rbp
push    rbx
mov     rax, rdi
xor     edi, edi
jmp     short loc_9C85
```

```asm
loc_9DAB:
add     rax, r8
sub     rcx, r8
mov     rdx, rcx
pop     rbx
pop     rbp
retn
; } // starts at 9C60
_ZN4core3str21_$LT$impl$u20$str$GT$12trim_matches17hb17aa2e5150f772eE endp
```

Through context we are aware that:

- Arguments passed into function: `rdi` - initial string address; `rsi` - initial string length
- Arguments returned from function: `rax` - trimmed string address; `rdx` - trimmed string length

`rax` remains completely untouched throughout the function, which means that `r8` will represent the number of bytes trimmed off.

Our goal is to trim off the first byte of our 1st number so that the new 7-byte number (sans final `0xff`) becomes the same as our 2nd number. Which means we want `r8` to end up to be `0x1` when we reach the tail code block.

Looking at the control flow graph we can identify two main groups of blocks which are pretty similar to each other. The final data in `r8` is modified only by the first block, and that in `rcx` the second. From this we can reasonably deduce that the two groups trim the start and the end of the string respectively. Hence we will be primarily focusing on the first group.

```asm
loc_9D24:
xor     r8d, r8d
mov     rdi, rcx
xor     r9d, r9d
jmp     short loc_9D3B
```

This is not where we want to end up in from the first group, as `r8` gets resetted to `0x0`. Instead we want to take the other path out of the first group:

```asm
loc_9C73:
sub     rdi, rax
mov     r8, rcx
mov     r9, rdi
cmp     r10d, edx
jnz     loc_9D3B
```

Very evidently it is part of a larger loop surrounding the first group:

```asm
loc_9C85:
cmp     rdi, rsi
jz      loc_9D19
mov     rcx, rdi
add     rdi, rax
movzx   r10d, byte ptr [rdi]
test    r10b, r10b
jns     short loc_9C70
```

To exit the loop (see `loc_9C73`), `r10d` must not be equal to `edx`, which remains unchanged being `0x0`. Before that desired `r8` information is stored in `rcx`, which is only changed at the start of the loop (see `loc_9C85`), `mov rcx, rdi`, where `rdi` acts as the "current index" of the loop. Thus we need to:

- Go through the `inc rdi` branch once
- Go through any branch once, this time with `r10d != 0x0`

The `inc rdi` branch is easy to trigger:

```asm
loc_9C70:
inc     rdi
```

Combined with `loc_9C85`, we just need the first byte to not have its MSB set (i.e. `< 0x80`). Combined with `loc_9C73` (the end of the loop), the byte needs to be `0x0` so that the loop continues running.

The next byte will conversely need to have its MSB set, as we don't want to enter the `inc rdi` branch again (that will be too much). The next branch is:

```asm
mov     r8d, r10d
and     r8d, 1Fh
movzx   r11d, byte ptr [rdi+1]
and     r11d, 3Fh
cmp     r10b, 0DFh
jbe     short loc_9CF3
```

If the jump is not taken, the program flows towards the end of the loop (`loc_9C73`).

```asm
loc_9CF3:
add     rdi, 2
shl     r8d, 6
or      r8d, r11d
mov     r10d, r8d
jmp     loc_9C73
```

By the end of this block `r10d` needs to be nonzero. We see that this is actually a pretty easy condition to meet:

```python
0x80 <= st[idx] < 0xe0
((st[idx] & 0x1f) << 6 | (st[idx+1] & 0x3f)) != 0
```

where `st` and `idx` are the string and current index respectively.

And that's actually it! Our 2 numbers are:

```python
0x01_00_00_00_00_00_83_00 # 72057594037961472
0xff_01_00_00_00_00_00_83 # 18374967954648334467
```

As strings they look like:

```python
b'\x00\x83\x00\x00\x00\x00\x00\x01'
b'\x83\x00\x00\x00\x00\x00\x01\xff'
```

1. The first `0x00` in the 1st number gets skipped
2. The second and first bytes fulfill the conditions in the first group of code blocks, so the trimming stops
3. `0xff` is appended to the 1st number, and thus ending up the same as the 2nd number.

Trying this out:

```
$ ./lucky_numbers_revenge_2
Luck is all you need!
Enter number #1:
72057594037961472
Enter number #2:
18374967954648334467
Correct
FLAG not set, please contact the admin
```

```
flag{b00f1a2d7474e1414b52771d37304e337798fdebcfe5efd71}
```

---

## Appendix

While writing this writeup I've decided to take a closer look at the `trim_matches` function again. I was puzzled by the `0x80`, `0xE0`, `0xF0` branches until something finally clicked: `UTF-8` encoding! (Wikipedia has a nice [chart](https://en.wikipedia.org/wiki/UTF-8#Encoding) that really highlights the similarities.)

The function simply converts the `UTF-8`-assumed bytes to code points and trims them off if the resulting code points match `edx` (which is `0x0` in this case).
