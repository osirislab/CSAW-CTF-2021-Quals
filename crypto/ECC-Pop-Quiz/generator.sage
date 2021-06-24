from random import randint
import json
from Crypto.Util.number import getPrime

with open("flag.txt",'r') as f:
	flag = f.read()

def smarts_attack():
	with open("smarts_attack_curves.json",'r') as f:
		curves = json.loads(f.read())
	index = randint(0,len(curves)-1)
	p = int(curves[index]['field']['p'],16)
	a = int(curves[index]['a'],16)
	b = int(curves[index]['b'],16)
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
	return secret

def mov_attack():
	with open("mov_attack_curves.json",'r') as f:
		curves_mov = json.loads(f.read())
	

def singular_curves():
	p = getPrime(128)
	F = GF(p)
	a,b = -3,2
	

def main():
	print("Part 1 --> Are you smart enough to crack this?\n")
	smarts = smarts_attack()
	while True:
		n = int(input("\nWhat is the value of 'secret'?: "))
		if n == smarts:
			print("Success!")
			break
		else:
			print("Failed!")
	
	"""print("\nPart 2\n")
	mov = mov_attack()
	while True:
		n = int(input("\nWhat is the value of 'secret'?: "))
		if n == secret:
			print("Success!")
			break
		else:
			print("Failed!")"""
	
	print("\nPart 3\n")
	singular = singular_curves()
	while True:
		n = int(input("\nWhat is the value of 'secret'?: "))
		if n == singular:
			print("Success!")
			break
		else:
			print("Failed!")
	
	print("\nCongrats on passing the ECC Pop Quiz! Here is your flag:",flag)

if __name__ == "__main__":
	main()
