from Crypto.Util.number import inverse
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes,bytes_to_long

def RSA_function(plain):
    ##### RSA key.dat
    n = 126419
    e = 30743
    #use http://factordb.com/ input n get p, q
    p = 167
    q = 757
    #φ(n) = (p-1)*(q-1)
    r = (p-1)*(q-1)
    #e * d % φ(n) = 1
    d = 55439 # inverse(e,r)

    #####
    m = bytes_to_long(plain)
    c = pow(m,e,n) #cipher = m ** e % n
    print('cipher: ',long_to_bytes(c))
    m = pow(c,d,n) #plain_text = c ** d % n
    print('plain: ',long_to_bytes(m))
    return long_to_bytes(m)
def RSA_Decoder(cipher):
        ##### RSA key.dat
    n = 126419
    e = 30743
    #use http://factordb.com/ input n get p, q
    p = 167
    q = 757
    #φ(n) = (p-1)*(q-1)
    r = (p-1)*(q-1)
    #e * d % φ(n) = 1
    d = 55439 # inverse(e,r)

    #####
    #print(cipher)
    c = bytes_to_long(cipher)
    m = pow(c,d,n) #plain_text = c ** d % n
    #print('plain: ',long_to_bytes(m))
    return long_to_bytes(m)
key = RSA.construct((126419,30743,55439))
f = open('/home/victim/Desktop/theme','rb')
cipher = f.read()
f.close()

plain = b''
plain2 = b''
part_cipher = [cipher[i:i+2] for i in range(0,len(cipher),2)]
for part in part_cipher:
    plain += key.decrypt(part)
    plain2 += RSA_Decoder(part)
print(plain)
print(plain2)