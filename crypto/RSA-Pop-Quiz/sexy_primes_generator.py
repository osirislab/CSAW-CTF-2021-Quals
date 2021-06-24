from Crypto.Util.number import getPrime, bytes_to_long
from sympy import isprime

m_bytes = b'testing'
m = bytes_to_long(m_bytes)

while True:
	p = getPrime(512)
	q = p + 6
	e = 65537
	if isprime(q):
		print("p =",p)
		print("q =",q)
		N = p*q
		phi = (p-1)*(q-1)
		d = pow(e,-1,phi)
		print("d =",d)
		print("N =",N)
		print("e =",e)
		print("c =",pow(m,e,N))
		break
