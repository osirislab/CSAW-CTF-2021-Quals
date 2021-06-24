from Crypto.Util.number import getPrime, bytes_to_long
import random

m_bytes = b'testing'
m = bytes_to_long(m_bytes)

p = getPrime(512)
q = getPrime(512)
N = p*q
phi = (p-1)*(q-1)
while True:
	try:
		d = random.randint(2,pow(N,1/4)//3)
		e = pow(d,-1,phi)
		break
	except:
		continue

print("p =",p)
print("q =",q)
print("d =",d)
print("N =",N)
print("e =",e)
print("c =",pow(m,e,N))
