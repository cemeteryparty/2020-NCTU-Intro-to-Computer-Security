from pwn import *

r = remote('140.113.207.233',8821)
"""
$ gdb you_should_read_manual
> pdisass main # you will see random store at eax
> b main # breakpoint at main
> r # run until rand(), check the value in eax
"""
random = 0x6b8b4567
r.sendline(str(random ^ 0xdeadbeaf))
r.interactive()
