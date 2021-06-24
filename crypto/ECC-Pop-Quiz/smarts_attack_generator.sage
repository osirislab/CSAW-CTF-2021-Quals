from random import randint
import json

with open("smarts_attack_curves.json",'r') as f:
	curves = json.loads(f.read())

index = randint(0,len(curves)-1)

p = int(curves[index]['field']['p'],16)
a = int(curves[index]['a'],16)
b = int(curves[index]['b'],16)

# Define curve
E = EllipticCurve(GF(p), [a, b])

print("The curve parameters are:")
print("p =",p)
print("a =",a)
print("b =",b)

P1 = E.gens()[0]
print(f'\nP1: {P1}')

secret = randint(1, E.order() - 1)
P2 = secret * P1
print(f'P2: {P2}')
print('P2 = secret * P1')

while True:
	n = input("\nWhat is the value of 'secret'?: ")
	if n == str(secret):
		print("Success!")
		break
	else:
		print("Failed!")
