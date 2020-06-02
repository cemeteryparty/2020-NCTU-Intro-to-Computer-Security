"""
fin = open("crack_me.log",'r')
s = fin.read()
fin.close()
for i in range(0,256):
    tmp = ''
    for si in range(0,len(s)):
        tmp += chr(ord(s[si]) ^ i)
    print('key = {:d}:{}'.format(i,tmp))
"""
plain = 'Verification_flag:0716085\n'
cipher = ''
for i in range(0,len(plain)):
    cipher += chr(ord(plain[i]) ^ 133)
fout = open("task1_result.log",'w')
fout.write(cipher)
fout.close()

fin = open("task1_result.log",'r')
cipher = fin.read()
fin.close()
plain = ''
for i in range(0,len(cipher)):
    plain += chr(ord(cipher[i]) ^ 133)
print(plain)