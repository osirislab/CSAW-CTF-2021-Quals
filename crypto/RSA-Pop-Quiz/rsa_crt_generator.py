from Crypto.Util.number import getPrime, bytes_to_long

m_bytes = b'testing'
m = bytes_to_long(m_bytes)

while True:
	p = getPrime(512)
	q = getPrime(512)
	N = p*q
	phi = (p-1)*(q-1)
	e = 65537
	d = pow(e,-1,phi)
	dp = d % (p-1)
	dq = d % (q-1)
	qinv = pow(q,-1,p)
	if dp < 2**200 and dq < 2**200:
		break

print("p =",p)
print("q =",q)
print("d =",d)
print("dp =",dp)
print("dq =",dq)
print("qinv =",qinv)
print("N =",N)
print("e =",e)
print("c =",pow(m,e,N))
