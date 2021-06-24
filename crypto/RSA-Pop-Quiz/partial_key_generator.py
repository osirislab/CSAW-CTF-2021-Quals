from Crypto.Util.number import getPrime, bytes_to_long

m_bytes = b'testing'
m = bytes_to_long(m_bytes)

while True:
	try:
		p = getPrime(512)
		q = getPrime(512)
		N = p*q
		phi = (p-1)*(q-1)
		e = 17
		d = pow(e,-1,phi)
		break
	except:
		continue

print("p =",p)
print("q =",q)
print("d =",d)
print("N =",N)
print("e =",e)
print("d0 =",int(bin(d)[-512:],2))
print("c =",pow(m,e,N))
print("d0bits = 512")
print("nBits = 1024")
