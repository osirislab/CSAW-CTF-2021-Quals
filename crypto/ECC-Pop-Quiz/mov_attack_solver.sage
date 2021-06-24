# Curve parameters --> Replace the next three lines with given values
p = 325123080912906649178181191307324899933
a = 0
b = 1

# Define curve
E = EllipticCurve(GF(p), [a, b])
order = E.order()
print(is_prime(order))

# Replace the next two lines with given values
P1 = E(124556068645057338380771714502532714210 , 228761596578706057395092255392100224637)
P2 = E(191642239889982926313263865049824333391 , 196465992158475023050622406861132079586)
Po = P1.order()

k = 1
while (p**k - 1) % order:
    k += 1

F2.<x> = GF(p^k)
E2 = E.change_ring(F2)
P2 = E2(P1)
Q2 = E2(P2)

while True:
	R = E2.random_point()
	Ro = R.order()
	g = gcd(Ro, Po)
	S = (Ro//g)*R
	So = S.order()
	if Po/So in ZZ and Po == So:
		break

print("Finding the pairings")
alpha = P2.weil_pairing(S,Po)
beta = Q2.weil_pairing(S,Po)
print("Computing the log")
dd = beta.log(alpha)
print(dd)
