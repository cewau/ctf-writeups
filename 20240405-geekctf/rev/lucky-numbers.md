# lucky numbers

Category: `rev`

Points: `289`

Solves: 9

Description:

> In Rust we Trust, right? Right..?

---

Wow, it is a Rust binary. Even the decompilation still looks annoying. Maybe we can take a look at its functionality first:

```
$ ./lucky_numbers
Luck is all you need!
Enter number #1:
1
Enter number #2:
2
Wrong
```

Let's start from the back. We can clearly see the strings `Correct` and `Wrong` in the binary, so where are they referenced? Turns out, they are accessed through a comparison instruction:

```asm
.text:000000000000975F                 cmp     rax, rcx
.text:0000000000009762                 jnz     loc_9816
.text:0000000000009768                 lea     rax, off_590F8  ; "Correct\n\nFLAG not set, please contact"...
; ...
.text:0000000000009816 loc_9816:                               ; CODE XREF: lucky_numbers::main::h7d02f80aefad9194+822↑j
.text:0000000000009816                 lea     rax, off_590E8  ; "Wrong\nCorrect\n\nFLAG not set, please "...
```

Before that, the data goes through a very convoluted set of operations, and perhaps so to make it a one-way function. Either way, after meticulous data flow tracing (or honestly just by educated guess), we know that the 2 variables run through the same set of operations independently of each other before they are compared against each other.

---

So where do the 2 variables come from? For this, we can set a breakpoint at the second call (or rather third, as the first chunk had two similar calls together) to `Hasher.write`:

```
gef➤  b *0x55555555d584
Breakpoint 1 at 0x55555555d584
gef➤  r
...
Luck is all you need!
Enter number #1:
1234
Enter number #2:
5678
...
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555d575 <lucky_numbers::main+1589> lea    rdi, [rsp+0x8]
   0x55555555d57a <lucky_numbers::main+1594> lea    rsi, [rsp+0x50]
   0x55555555d57f <lucky_numbers::main+1599> mov    edx, 0x8
●→ 0x55555555d584 <lucky_numbers::main+1604> call   0x55555555cd60 <_ZN71_$LT$core..hash..sip..Hasher$LT$S$GT$$u20$as$u20$core..hash..Hasher$GT$5write17h3c7e831bf43deea8E>
   ↳  0x55555555cd60 <<core::hash::sip::Hasher<S>+0> push   rbx
      0x55555555cd61 <<core::hash::sip::Hasher<S>+0> add    QWORD PTR [rdi+0x30], rdx
      0x55555555cd65 <<core::hash::sip::Hasher<S>+0> mov    r9, QWORD PTR [rdi+0x40]
      0x55555555cd69 <<core::hash::sip::Hasher<S>+0> test   r9, r9
      0x55555555cd6c <<core::hash::sip::Hasher<S>+0> je     0x55555555cd9d <_ZN71_$LT$core..hash..sip..Hasher$LT$S$GT$$u20$as$u20$core..hash..Hasher$GT$5write17h3c7e831bf43deea8E+61>
      0x55555555cd6e <<core::hash::sip::Hasher<S>+0> mov    r8d, 0x8
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
_ZN71_$LT$core..hash..sip..Hasher$LT$S$GT$$u20$as$u20$core..hash..Hasher$GT$5write17h3c7e831bf43deea8E (
   $rdi = 0x007fffffffdcc8 → "uespemosarenegylmodnarodsetybdet",
   $rsi = 0x007fffffffdd10 → 0x000000000000162e,
   $rdx = 0x00000000000008,
   $rcx = 0x00000000000010
)
```

Referencing the [`Hasher` struct](https://doc.rust-lang.org/src/core/hash/sip.rs.html#49), we see that the (sets of) variables involved in the convoluted operations that follow come from the fields of the struct.

Before proceeding, we shall also look at how the input data is handled. We can see that the (third) `Hasher.write` definitely took our second number as input (`0x162e` = 5678). I couldn't stand the decompilation, so I analysed the assembly directly instead.

```asm
lea     rax, off_590C0  ; "Enter number #2:\nWrong\nCorrect\n\nFLA"...
```

We are about to input the 2nd number.

```
lea     rdi, [rsp+198h+var_190]
lea     rsi, [rsp+198h+var_148]
lea     rdx, [rsp+198h+var_B0]
call    cs:_ZN3std2io5stdio5Stdin9read_line17hd69be319c012e486E_ptr ; std::io::stdio::Stdin::read_line::hd69be319c012e486 ...
cmp     [rsp+198h+var_190], 0
jnz     loc_99CB
```

The input buffer is located in the struct at `var_B0`.

```
mov     rdi, [rsp+198h+var_A8]
mov     rsi, [rsp+198h+var_A0]
call    _ZN4core3str21_$LT$impl$u20$str$GT$12trim_matches17hb3529f68d9fac40bE ; core::str::_$LT$impl$u20$str$GT$::trim_matches::hb3529f68d9fac40b
lea     rdi, [rsp+198h+var_118]
mov     rsi, rax
call    cs:_ZN4core3num62_$LT$impl$u20$core__str__traits__FromStr$u20$for$u20$usize$GT$8from_str17hc6f75507e28d8f4dE_ptr_0 ; core::num::_$LT$impl$u20$core..str..traits..FromStr$u20$for$u20$usize$GT$::from_str::hc6f75507e28d8f4d ...
cmp     byte ptr [rsp+198h+var_118], 0
jz      loc_9376
```

`var_A8` and `var_A0` reference the string (address) and length respectively. The result of `trim_matches` is passed to the next function `from_str`, the result of which is stored in `var_118` (as a struct, probably `Result`). The numeric value itself is stored in `var_110` (8 bytes below).

```
mov     rax, [rsp+198h+var_110]
mov     [rsp+198h+var_78], rax
```

The value is then transferred to `var_78`.

```
mov     rax, [rsp+198h+var_78]
mov     [rsp+198h+var_148], rax
lea     rdi, [rsp+198h+var_190]
lea     rsi, [rsp+198h+var_148]
mov     edx, 8
call    _ZN71_$LT$core__hash__sip__Hasher$LT$S$GT$$u20$as$u20$core__hash__Hasher$GT$5write17h3c7e831bf43deea8E ; _$LT$core..hash..sip..Hasher$LT$S$GT$$u20$as$u20$core..hash..Hasher$GT$::write::h3c7e831bf43deea8
```

Finally, the value is used in the `Hasher.write` function.

---

Now we play around with the `Hasher.write`(s) revolving around the 1st number.

```
gef➤  b *0x55555555d46e
Breakpoint 1 at 0x55555555d46e
gef➤  b *0x55555555d485
Breakpoint 2 at 0x55555555d485
gef➤  r
...
Luck is all you need!
Enter number #1:
1234
Enter number #2:
5678
...
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
_ZN71_$LT$core..hash..sip..Hasher$LT$S$GT$$u20$as$u20$core..hash..Hasher$GT$5write17h3c7e831bf43deea8E (
   $rdi = 0x007fffffffdd40 → "uespemosarenegylmodnarodsetybdet",
   $rsi = 0x005555555b3c40 → 0x00000000000004d2,
   $rdx = 0x00000000000002
)
...
gef➤  c
...
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
_ZN71_$LT$core..hash..sip..Hasher$LT$S$GT$$u20$as$u20$core..hash..Hasher$GT$5write17h3c7e831bf43deea8E (
   $rdi = 0x007fffffffdd40 → "uespemosarenegylmodnarodsetybdet",
   $rsi = 0x007fffffffdcc8 → 0x00000000000000ff,
   $rdx = 0x00000000000001
)
...
gef➤  ni
...
$rdi   : 0x007fffffffdd40  →  "uespemosarenegylmodnarodsetybdet"
...
```

```
gef➤  r
...
Luck is all you need!
Enter number #1:
1234567890123456789
Enter number #2:
1
...
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
_ZN71_$LT$core..hash..sip..Hasher$LT$S$GT$$u20$as$u20$core..hash..Hasher$GT$5write17h3c7e831bf43deea8E (
   $rdi = 0x007fffffffdd40 → "uespemosarenegylmodnarodsetybdet",
   $rsi = 0x005555555b3c40 → 0x112210f47de98115,
   $rdx = 0x00000000000008
)
...
gef➤  c
...
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
_ZN71_$LT$core..hash..sip..Hasher$LT$S$GT$$u20$as$u20$core..hash..Hasher$GT$5write17h3c7e831bf43deea8E (
   $rdi = 0x007fffffffdd40 → 0x950ca4bd12ad9253,
   $rsi = 0x007fffffffdcc8 → 0x00000000000000ff,
   $rdx = 0x00000000000001
)
```

Here we learn that the `Hasher` takes in 8 bytes before the `State` changes. For the 1st `Hasher`, it `write`s a number of bytes equal to the length of the input number, then writes an additional `0xff`. For the 2nd `Hasher`, it simply writes 8 bytes, treating the input number as a "string". These 2 `Hasher`s then form the basis for the long set of operations, ultimately comparing against each other.

Hence, getting them to match is [as simple as](https://users.rust-lang.org/t/hash-prefix-collisions/71823):

```
[1] 1234567890123456 -> gets converted to 000462d53c8abac0
[2] 18375921047561747136 (ff0462d53c8abac0)
```

```
$ ./lucky_numbers
Luck is all you need!
Enter number #1:
1234567890123456
Enter number #2:
18375921047561747136
Correct
FLAG not set, please contact the admin
```

```
flag{THe_DeF@U17_HA5HEr_iS_n0T_cRYpt0GRAPHiC_s3CuRE}
```
