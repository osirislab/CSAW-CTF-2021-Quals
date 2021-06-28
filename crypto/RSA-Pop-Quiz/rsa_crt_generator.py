from sympy import isprime
from Crypto.Util.number import getPrime, GCD, inverse
import random, math

while True:
	e = getPrime(500)
	dp = random.randint(1 << 100, 1 << 200)
	dq = random.randint(1 << 100, 1 << 200)

	for k in range(2,1000000):
		p = (((e*dp)-1)//k) + 1
		if isprime(p):
			break

	for l in range(2,1000000):
		q = (((e*dq)-1)//l) + 1
		if isprime(q):
			break

	if p/q < 1/2 or p/q > 2 or GCD(e,p) != 1 or GCD(e,q) != 1:
		continue
	
	N = p*q
	phi = (p-1)*(q-1)
	d = inverse(e,phi)
	w = dp*dq
	x = dp*(l-1) + dq*(k-1)
	y = k*l
	z = k+l-1
	
	if GCD(y,x + w*e) == 1 and math.log(e,N) < 0.375 and math.log(dp) < 0.25*math.log(N) - math.log(3) and math.log(dq) < 0.25*math.log(N) - math.log(3):
		print("p =",p)
		print("q =",q)
		print("d =",d)
		print("dp =",dp)
		print("dq =",dq)
		print("k =",k)
		print("l =",l)
		print("w =",w)
		print("x =",x)
		print("y =",y)
		print("z =",z)
		print("N =",N)
		print("e =",e)
		print()
		break
