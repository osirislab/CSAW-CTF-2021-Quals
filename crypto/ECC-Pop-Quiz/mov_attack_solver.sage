# Curve parameters --> Replace the next three lines with given values
p = 26715668608298314141647233522012293003
a = 26715668608298314141647233522012293002
b = 0

# Define curve
E = EllipticCurve(GF(p), [a, b])
order = E.order()
print(is_prime(order))

# Replace the next two lines with given values
P1 = E(24166409859081021035853185167435581465 , 24392656442309501164435382417913623021)
P2 = E(5110634388699635634648935814056445376 , 7283632616912488220869842021257386953)
n = P1.order()

k = 1
while (p**k - 1) % order:
	k += 1

K.<a> = GF(p**k)
EK = E.base_extend(K)
PK = EK(P2)
GK = EK(P1)

while True:
	R = EK.random_point()
	m = R.order()
	d = gcd(m,n)
	Q = (m//d)*R
	if n / Q.order() not in ZZ:
		continue
	if n == Q.order():
		break

print('Computing pairings')
alpha = GK.weil_pairing(Q,n)
beta = PK.weil_pairing(Q,n)

print("Computing the log")
dd = beta.log(alpha)
print(dd)
