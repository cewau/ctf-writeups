# What's this

Category: `rev`

Points: `550`

Solves: 10

---

## Part I

We are given a pretty mysterious binary. For starters, we can't even run it regularly.

```bash
$ ./chall
zsh: exec format error: ./chall
```

We can dive a bit deeper into its metadata:

```bash
$ file chall
chall: ELF 32-bit LSB executable, Motorola RCE, version 1 (SYSV), dynamically linked, interpreter /lib/ld.so.1, for GNU/Linux 5.10.0, stripped
```

It *is* at least an ELF. But the architecture looks really exotic. Motorola RCE?

```bash
$ readelf -h chall
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           MCORE
  Version:                           0x1
  Entry point address:               0x8450
  Start of program headers:          52 (bytes into file)
  Start of section headers:          4540 (bytes into file)
  Flags:                             0x20006008
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         8
  Size of section headers:           40 (bytes)
  Number of section headers:         26
  Section header string table index: 25
```

There is practically zero information online regarding `MCORE` or `Motorola RCE` or whatever. We *are* however at least able to find the architecture documentation: [[1](https://web.archive.org/web/20220705150956/https://www.nxp.com/docs/en/reference-manual/MCOREABISM.pdf)] and [[2](https://web.archive.org/web/20160304090032/http://www.saladeteletipos.com/pub/SistemasEmbebidos2006/PlacaMotorola/mcore_rm_1.pdf)]. Even better, `radare2` actually supports `MCORE` disassembly for some reason.

```
$ r2 chall
Unsupported relocs type 1 for arch 39
Unsupported relocs type 1 for arch 39
Unsupported relocs type 11 for arch 39
...
[0x00008450]> aaaa
...
[0x00008450]> pdf
            ;-- section..text:
            ;-- pc:
            ; UNKNOWN XREF from segment.LOAD0 @ +0x18
┌ 6: entry0 ();
│ bp: 0 (vars 0, args 0)
│ sp: 0 (vars 0, args 0)
│ rg: 0 (vars 0, args 0)
│           0x00008450      2214           rsub r2, r2                 ; [10] -r-x section size 800 named .text
│       ┌─< 0x00008452      0fea           bf 0x8662
└       │   0x00008454      0000           bkpt
[0x00008450]> pd @ 0x8662
            ; CODE XREF from entry0 @ 0x8452
            0x00008662      0120           addi r1, r1, 0x0
            0x00008664      0ed9           st.h r9, (r14, 0x0)
            0x00008666      0020           addi r0, r0, 0x0
            0x00008668      0214           rsub r2, r0
            ; CODE XREF from aav.0x00008540 @ +0x6
            0x0000866a      3c78           lrw r0, (r60, 0x20)
            0x0000866c      1704           subu r7, r1
            0x0000866e      0000           bkpt
            0x00008670      .dword 0x000087ec ; str.Input_your_flag:_
            ;-- aav.0x00008674:
            ; UNKNOWN XREF from section..rela.dyn @ +0x9c
            0x00008674      0000           bkpt
            0x00008676      0000           bkpt
            0x00008678      .dword 0x00008800 ; str._80s
...
```

Unfortunately that is not what we like to see. The disassembly just seems... weird. Or even wrong. Many parts of it just don't make sense, such as random null bytes in the middle of nowhere.

Over here I spent quite a long time digging for answers, and eventually I found something interesting.

```bash
$ readelf -S chall
There are 26 section headers, starting at offset 0x11bc:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        00008134 000134 00000d 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            00008144 000144 000020 00   A  0   0  4
  [ 3] .hash             HASH            00008164 000164 00003c 04   A  4   0  4
  [ 4] .dynsym           DYNSYM          000081a0 0001a0 0000a0 10   A  5   1  4
  [ 5] .dynstr           STRTAB          00008240 000240 0000a2 00   A  0   0  1
  [ 6] .gnu.version      VERSYM          000082e2 0002e2 000014 02   A  4   0  2
  [ 7] .gnu.version_r    VERNEED         000082f8 0002f8 000020 00   A  5   1  4
  [ 8] .rela.dyn         RELA            00008318 000318 0000cc 0c   A  4   0  4
  [ 9] .init             PROGBITS        000083f0 0003f0 00005c 00  AX  0   0 16
  [10] .text             PROGBITS        00008450 000450 000320 00  AX  0   0 16
  [11] .fini             PROGBITS        00008770 000770 000028 00  AX  0   0 16
  [12] .rodata           PROGBITS        00008798 000798 00009a 00   A  0   0  4
  [13] .eh_frame_hdr     PROGBITS        00008834 000834 000014 00   A  0   0  4
  [14] .eh_frame         PROGBITS        00008848 000848 00002c 00   A  0   0  4
  [15] .ctors            PROGBITS        00009f1c 000f1c 000008 00  WA  0   0  4
  [16] .dtors            PROGBITS        00009f24 000f24 000008 00  WA  0   0  4
  [17] .jcr              PROGBITS        00009f2c 000f2c 000004 00  WA  0   0  4
  [18] .dynamic          DYNAMIC         00009f30 000f30 0000d0 08  WA  5   0  4
  [19] .got              PROGBITS        0000a000 001000 000014 04  WA  0   0  4
  [20] .data             PROGBITS        0000a014 001014 000008 00  WA  0   0  4
  [21] .bss              NOBITS          0000a01c 00101c 000008 00  WA  0   0  4
  [22] .comment          PROGBITS        00000000 00101c 000021 01  MS  0   0  1
  [23] .csky.attributes  LOPROC+0x1      00000000 00103d 00000f 00      0   0  1
  [24] .csky_stack_size  PROGBITS        00000000 001050 000084 00      0   0 16
  [25] .shstrtab         STRTAB          00000000 0010d4 0000e6 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), p (processor specific)
```

There are a few mentions to `cksy` littered around the program. Looking it up online we quickly realise that it is essentially the "continuation" of `MCORE`. In particular,

> [V1 is derived from the MCore architecture while V2 is substantially different, with mixed 16- and 32-bit instructions, a larger register set, a different (but overlapping) ABI, etc.](https://reverseengineering.stackexchange.com/a/14603)

Interestingly though, `C-SKY` and `MCORE` share the same architecture code (39).

We can also find some `C-SKY` documentation online: [[1](https://github.com/c-sky/csky-doc/blob/master/C-SKY_V2_CPU_Applications_Binary_Interface_Standards_Manual.pdf)] and [[2](https://github.com/c-sky/csky-doc/blob/master/CSKY%20Architecture%20user_guide.pdf)]. In particular, the mask `0x20000000` in `e_flags` denotes `C-SKY V2`, which we now know has a completely different disassembly from `C-SKY V1` and `MCORE`.

---

## Part II

Unfortunately I couldn't find a tool to disassemble `C-SKY V2`. I tried to build `C-SKY`'s provided `objdump` to disassemble the binary, but while it was able to cleanly spit out the instructions, it did not generate the disassembly for some reason.

So I did it by hand instead.

As mentioned above, `V2` uses a mix of 16- and 32-bit instructions. This is determined by the 2 MSBs at the start of each word, where the next 2 words are to be parsed as a single 32-bit instruction if **both** MSBs of the first word are set.

First I prettified the `objdump` output into something more workable:

```python
with open('./disasm.txt') as f:
    RAW = f.read().splitlines()

with open('./disasm2.txt', 'w') as f:
    for line in RAW[:-1]:
        l, h, _ = tuple(line.split(' | '))
        h = h.strip()
        b = ' '.join(f'{int(h[i*2:(i+1)*2], 16):08b}' for i in range(len(h)//2))
        f.write(f'{l:4} | {h:8} | {b:35} | \n')
```

```
8450 | 1422     | 00010100 00100010                   | 
8452 | ea0f0000 | 11101010 00001111 00000000 00000000 | 
8456 | 9822     | 10011000 00100010                   | 
8458 | 1a03     | 00011010 00000011                   | 
845a | b842     | 10111000 01000010                   | 
845c | b801     | 10111000 00000001                   | 
845e | 1007     | 00010000 00000111                   | 
8460 | b800     | 10111000 00000000                   | 
8462 | 1007     | 00010000 00000111                   | 
8464 | 1067     | 00010000 01100111                   | 
8466 | ea9a0008 | 11101010 10011010 00000000 00001000 | 
846a | e8fa0000 | 11101000 11111010 00000000 00000000 | 
846e | ea9a0007 | 11101010 10011010 00000000 00000111 | 
8472 | e8fa0000 | 11101000 11111010 00000000 00000000 | 
8476 | 0000     | 00000000 00000000                   | 
; ...
```

Particularly because the opcode masks were not searchable from the documentation, which meant I had to reference [this](https://github.com/c-sky/binutils-gdb/blob/binutils-2_27-branch-csky/opcodes/csky-opc.h) instead and cross-reference with the actual documentation for what each mnemonic does.

This time though, the disassembly looked way more legit. For example, here is what the above snippet looks like:

```
8450 | 1422     | 00010100 00100010                   | sub   sp,  0x8
8452 | ea0f0000 | 11101010 00001111 00000000 00000000 | mov   r15, 0x0
8456 | 9822     | 10011000 00100010                   | mov   r1,  [sp+0x8]
8458 | 1a03     | 00011010 00000011                   | lea   r2,  [sp+0xc]
845a | b842     | 10111000 01000010                   | mov   [sp+0x8], r2
845c | b801     | 10111000 00000001                   | mov   [sp+0x4], r0
845e | 1007     | 00010000 00000111                   | mov   r0,  [pc+0x1c]  ; 0x847a (0x8478) -> 0x00008734
8460 | b800     | 10111000 00000000                   | mov   [sp+0x0], r0
8462 | 1007     | 00010000 00000111                   | mov   r0,  [pc+0x1c]  ; 0x847e (0x847c) -> 0x00008574
8464 | 1067     | 00010000 01100111                   | mov   r3,  [pc+0x1c]  ; 0x8480 -> 0x0000869c
8466 | ea9a0008 | 11101010 10011010 00000000 00001000 | mov   r26, [pc+0x20] ; 0x8486 (0x8484) -> 0x00000000
846a | e8fa0000 | 11101000 11111010 00000000 00000000 | call  r26            ; link and jump (r15 = pc+4)
846e | ea9a0007 | 11101010 10011010 00000000 00000111 | mov   r26, [pc+0x1c] ; 0x848a (0x8488) -> 0x00000000
8472 | e8fa0000 | 11101000 11111010 00000000 00000000 | call  r26
8476 | 0000     | 00000000 00000000                   | 
```

**Side note:** Obviously this is not the real disassembly. I just wrote it in "Intel-like syntax" so that I myself could understand it better.

Things that tripped me up:

* When each instruction is executed, the `pc` is still *at the start* of that instruction, instead of *after the end*.
* The `pc`-relative load instructions have the last *x* bits cleared presumably for alignment. For word loading the last 2 bits are cleared.
* Notice above some of the addresses still point to `0x00000000`. My guess is that they are where the dynamically linked libc functions are located afterwards.

Scrolling through the disassembly, our attention is brought to this section:

```
8670 | 87ec     | 10000111 11101100                   | ; Input your flag: 
8672 | 0000     | 00000000 00000000                   | 
8674 | 00000000 | 00000000 00000000 00000000 00000000 | 
8678 | 8800     | 10001000 00000000                   | ; %80s
867a | 0000     | 00000000 00000000                   | 
867c | 00000000 | 00000000 00000000 00000000 00000000 | 
8680 | 00000000 | 00000000 00000000 00000000 00000000 | 
8684 | 8808     | 10001000 00001000                   | ; Length error
8686 | 0000     | 00000000 00000000                   | 
8688 | 879c     | 10000111 10011100                   | 
868a | 0000     | 00000000 00000000                   | 
868c | 87c4     | 10000111 11000100                   | 
868e | 0000     | 00000000 00000000                   | 
8690 | 8818     | 10001000 00011000                   | ; Wrong flag!
8692 | 0000     | 00000000 00000000                   | 
8694 | 8824     | 10001000 00100100                   | ; Correct flag!
8696 | 0000     | 00000000 00000000                   | 
8698 | 6c03     | 01101100 00000011                   | 
869a | 0000     | 00000000 00000000                   | 
```

This is where the string and libc function pointers seem to be stored. The section right above contains quite a lot of `pc`-relative load instructions, and they all point to this section.

After painstakingly disassembling the section:

```
8574 | 1422     | 00010100 00100010                   | sub   sp,  0x8
8576 | dd0e2000 | 11011101 00001110 00100000 00000000 | mov   dword ptr [sp], r8
857a | ddee2001 | 11011101 11101110 00100000 00000001 | mov   dword ptr [sp+0x4], r15
857e | 6e3b     | 01101110 00111011                   | mov   r8,  sp
8580 | 143b     | 00010100 00111011                   | sub   sp,  0x6c
8582 | 111c     | 00010001 00011100                   | mov   r0,  [pc+0xf0] ; 0x8672 (0x8670) -> 0x000087ec -> "Input your flag: "
8584 | ea9a003c | 11101010 10011010 00000000 00111100 | mov   r26, [pc+0xf0] ; 0x8674 -> 0x00000000 ==================================== puts
8588 | e8fa0000 | 11101000 11111010 00000000 00000000 | call  r26
858c | e468106b | 11100100 01101000 00010000 01101011 | lea   r3,  [r8-0x6c]
8590 | 6c4f     | 01101100 01001111                   | mov   r1,  r3
8592 | 111a     | 00010001 00011010                   | mov   r0,  [pc+0xe8] ; 0x867a (0x8678) -> 0x00008800 -> "%80s"
8594 | ea9a003a | 11101010 10011010 00000000 00111010 | mov   r26, [pc+0xe8] ; 0x867c -> 0x00000000 ==================================== scanf
8598 | e8fa0000 | 11101000 11111010 00000000 00000000 | call  r26
859c | e468106b | 11100100 01101000 00010000 01101011 | lea   r3,  [r8-0x6c]
85a0 | 6c0f     | 01101100 00001111                   | mov   r0,  r3
85a2 | ea9a0038 | 11101010 10011010 00000000 00111000 | mov   r26, [pc+0xe0] ; 0x8682 (0x8680) -> 0x00000000 ==================================== strlen
85a6 | e8fa0000 | 11101000 11111010 00000000 00000000 | call  r26
85aa | 6c83     | 01101100 10000011                   | mov   r2,  r0
85ac | e4681007 | 11100100 01101000 00010000 00000111 | lea   r3,  [r8-0x8]
85b0 | b340     | 10110011 01000000                   | mov   [r3], r2
85b2 | e4681007 | 11100100 01101000 00010000 00000111 | lea   r3,  [r8-0x8]
85b6 | 9360     | 10010011 01100000                   | mov   r3,  [r3]
85b8 | eb430025 | 11101011 01000011 00000000 00100101 | cmpne r3,  0x25
85bc | 0c08     | 00001100 00001000                   | jne   0x10           ; 0x85cc
;
85be | 1112     | 00010001 00010010                   | mov   r0,  [pc+0xc8] ; 0x8686 (0x8684) -> 0x00008808 -> "Length error"
85c0 | ea9a002d | 11101010 10011010 00000000 00101101 | mov   r26, [pc+0xb4] ; 0x8674 -> 0x00000000 ==================================== puts
85c4 | e8fa0000 | 11101000 11111010 00000000 00000000 | call  r26
85c8 | 3300     | 00110011 00000000                   | mov   r3,  0x0
85ca | 0449     | 00000100 01001001                   | jmp   0x92           ; 0x865c
; xref from 0x85bc
85cc | e4681000 | 11100100 01101000 00010000 00000000 | lea   r3,  [r8-0x1]
85d0 | 3200     | 00110010 00000000                   | mov   r2,  0x0
; xref from 0x864e
85d2 | a340     | 10100011 01000000                   | mov   byte ptr [r3], r2
85d4 | 0437     | 00000100 00110111                   | jmp   0x6e           ; 0x8642
;
85d6 | e4681000 | 11100100 01101000 00010000 00000000 | lea   r3,  [r8-0x1]
85da | 8360     | 10000011 01100000                   | mov   r3,  byte ptr [r3]
85dc | 74cc     | 01110100 11001100                   | zextb r3,  r3
85de | e448106b | 11100100 01001000 00010000 01101011 | lea   r2,  [r8-0x6c]
85e2 | d0620023 | 11010000 01100010 00000000 00100011 | mov   r3,  byte ptr[r3+r2]
85e6 | 748c     | 01110100 10001100                   | zextb r2,  r3
85e8 | e4681000 | 11100100 01101000 00010000 00000000 | lea   r3,  [r8-0x1]
85ec | 8360     | 10000011 01100000                   | mov   r3,  byte ptr [r3]
85ee | 74cc     | 01110100 11001100                   | zextb r3,  r3
85f0 | 1126     | 00010001 00100110                   | mov   r1,  [pc+0x98] ; 0x8688 -> 0x0000879c
85f2 | d0610023 | 11010000 01100001 00000000 00100011 | mov   r3,  byte ptr[r3+r1]
85f6 | 74cc     | 01110100 11001100                   | zextb r3,  r3 ; movzx r3, r3b
85f8 | 6cc9     | 01101100 11001001                   | xor   r3,  r2
85fa | 74cc     | 01110100 11001100                   | zextb r3,  r3
85fc | 748e     | 01110100 10001110                   | sextb r2,  r3 ; movsx r2, r3b
85fe | e4681000 | 11100100 01101000 00010000 00000000 | lea   r3,  [r8-0x1]
8602 | 8360     | 10000011 01100000                   | mov   r3,  byte ptr [r3]
8604 | 2300     | 00100011 00000000                   | add   r3,  0x1
8606 | 74cc     | 01110100 11001100                   | zextb r3,  r3
8608 | 74ce     | 01110100 11001110                   | sextb r3,  r3
860a | 6cc9     | 01101100 11001001                   | xor   r3,  r2
860c | 74ce     | 01110100 11001110                   | sextb r3,  r3
860e | 748c     | 01110100 10001100                   | zextb r2,  r3
8610 | e4681000 | 11100100 01101000 00010000 00000000 | lea   r3,  [r8-0x1]
8614 | 8360     | 10000011 01100000                   | mov   r3,  byte ptr [r3]
8616 | 74cc     | 01110100 11001100                   | zextb r3,  r3
8618 | 103d     | 00010000 00111101                   | mov   r1,  [pc+0x74] ; 0x868c -> 0x000087c4
861a | d0610023 | 11010000 01100001 00000000 00100011 | mov   r3,  byte ptr[r3+r1]
861e | 74cc     | 01110100 11001100                   | zextb r3,  r3
8620 | 64ca     | 01100100 11001010                   | cmpne r3,  r2
8622 | 0c08     | 00001100 00001000                   | jne   0x10           ; 0x8632
;
8624 | 101b     | 00010000 00011011                   | mov   r0,  [pc+0x6c] ; 0x8690 -> 0x00008818 -> "Wrong flag!"
8626 | ea9a0014 | 11101010 10011010 00000000 00010100 | mov   r26, [pc+0x50] ; 0x8676 (0x8674) -> 0x00000000 ==================================== puts
862a | e8fa0000 | 11101000 11111010 00000000 00000000 | call  r26
862e | 3300     | 00110011 00000000                   | mov   r3,  0x0
8630 | 0416     | 00000100 00010110                   | jmp   0x2c           ; 0x865c
; xref from 0x8622
8632 | e4681000 | 11100100 01101000 00010000 00000000 | lea   r3,  [r8-0x1]
8636 | 8360     | 10000011 01100000                   | mov   r3,  byte ptr [r3]
8638 | 748c     | 01110100 10001100                   | zextb r2,  r3
863a | e4681000 | 11100100 01101000 00010000 00000000 | lea   r3,  [r8-0x1]
863e | 2200     | 00100010 00000000                   | add   r2,  0x1
8640 | a340     | 10100011 01000000                   | mov   byte ptr [r3], r2
; xref from 0x85d4
8642 | e4681000 | 11100100 01101000 00010000 00000000 | lea   r3,  [r8-0x1]
8646 | 8360     | 10000011 01100000                   | mov   r3,  byte ptr [r3]
8648 | 748c     | 01110100 10001100                   | zextb r2,  r3
864a | 3324     | 00110011 00100100                   | mov   r3,  0x24
864c | 648c     | 01100100 10001100                   | cmp   r3,  r2
864e | 0bc4     | 00001011 11000100                   | jge   -0x7c          ; 0x85d2
8650 | 1011     | 00010000 00010001                   | mov   r0,  [pc+0x44] ; 0x8694 -> 0x00008824 -> "Correct flag!"
8652 | ea9a0009 | 11101010 10011010 00000000 00001001 | mov   r26, [pc+0x24] ; 0x8676 (0x8674) -> 0x00000000 ==================================== puts
8656 | e8fa0000 | 11101000 11111010 00000000 00000000 | call  r26
865a | 3300     | 00110011 00000000                   | mov   r3,  0x0
; xref from 0x85ca, 0x8630
865c | 6c0f     | 01101100 00001111                   | mov   r0,  r3
865e | 6fa3     | 01101111 10100011                   | mov   sp, r8
8660 | d9ee2001 | 11011001 11101110 00100000 00000001 | mov   r15, dword ptr [sp+0x4]
8664 | d90e2000 | 11011001 00001110 00100000 00000000 | mov   r8,  dword ptr [sp]
8668 | 1402     | 00010100 00000010                   | add   sp,  0x4
866a | 783c     | 01111000 00111100                   | ret
```

(Note that some of the disassembly might be slightly incorrect as I had to backtrack a few times to correct some mistakes.)

We can rewrite the above into a higher-level language:

```python
KEY = [None for _ in range(0x25)] # 0x879c
CHECK = [None for _ in range(0x25)] # 0x87c4

def main():
    inp = input('Enter your flag: ')[:80]
    if len(inp) != 0x25:
        print('Length error')
    else:
        for i in range(0x25):
            if inp[i]^KEY[i]^(i+1) != CHECK[i]:
                print('Wrong flag!')
                break
        else:
            print('Correct flag!')
```

And finally, we can very easily rev this function:

```python
with open('./chall', 'rb') as f:
    RAW = f.read()

SZ = 0x25
A_START = 0x7c4
B_START = 0x79c
print(bytes(x^y^(i+1) for i, (x, y) in enumerate(zip(RAW[A_START:A_START+SZ], RAW[B_START:B_START+SZ]))).decode())
```

```
flag{it_1s_CsKY_raTheR_th@n_M0torola}
```
