from Crypto.Util.number import getPrime, bytes_to_long
import random, math
from sympy import isprime

with open("flag.txt",'r') as f:
	flag = f.read()

m1 = "Weiner weiner chicken dinner" # For wiener's attack
m2 = "Man, these primes sure are sexy" # For sexy primes
m3 = "Wow, looks like this oracle is worthless" # For LSB oracle
m4 = "I'll be careful next time to not leak the key" # For partial key
m5 = "" # For RSA-CRT

def wiener_attack():
	m_bytes = bytes(m1,'utf-8')
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
	print("N =",N)
	print("e =",e)
	print("c =",pow(m,e,N))
	
def sexy_primes():
	m_bytes = bytes(m2,'utf-8')
	m = bytes_to_long(m_bytes)
	while True:
		p = getPrime(512)
		q = p + 6
		e = 65537
		if isprime(q):
			N = p*q
			phi = (p-1)*(q-1)
			d = pow(e,-1,phi)
			print("N =",N)
			print("e =",e)
			print("c =",pow(m,e,N))
			break

def lsb_oracle():
	m_bytes = bytes(m3,'utf-8')
	m = bytes_to_long(m_bytes)
	p = getPrime(512)
	q = getPrime(512)
	N = p*q
	phi = (p-1)*(q-1)
	e = 65537
	d = pow(e,-1,phi)
	print("N =",N)
	print("e =",e)
	print("c =",pow(m,e,N))
	for i in range(int(math.log(N,2))+1):
		given = int(input("\nWhat would you like to decrypt?: "))
		decrypt = pow(given,d,N)
		print("\nThe oracle responds with:",bin(decrypt)[-1])

def partial_key():
	m_bytes = bytes(m4,'utf-8')
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
	print("N =",N)
	print("e =",e)
	print("d0 =",int(bin(d)[-512:],2))
	print("c =",pow(m,e,N))
	print("d0bits = 512")
	print("nBits = 1024")

def rsa_crt():
	m_bytes = bytes(m5,'utf-8')
	m = bytes_to_long(m_bytes)

def main():
	print("Part 1 --> This is one of the most common RSA attacks in CTFs!\n")
	wiener_attack()
	while True:
		answer = input("\nWhat is the plaintext?: ")
		if answer == m1:
			print("Success!")
			break
		else:
			print("Failed!")
	
	print("Part 2 --> Sexy numbers were used to make the modulus!\n")
	sexy_primes()
	while True:
		answer = input("\nWhat is the plaintext?: ")
		if answer == m2:
			print("Success!")
			break
		else:
			print("Failed!")
	
	print("Part 3 --> Looks like there is a oracle which is telling the LSB of the plaintext. That will not help you, right?\n")
	lsb_oracle()
	while True:
		answer = input("\nWhat is the plaintext?: ")
		if answer == m3:
			print("Success!")
			break
		else:
			print("Failed!")
	
	print("Part 4 --> Oops, looks like I leaked part of the private key. Hope that doesn't come back to bite me\n")
	partial_key()
	while True:
		answer = input("\nWhat is the plaintext?: ")
		if answer == m4:
			print("Success!")
			break
		else:
			print("Failed!")
	
	"""print("Part 5\n")
	rsa_crt()
	while True:
		answer = input("\nWhat is the plaintext?: ")
		if answer == m5:
			print("Success!")
			break
		else:
			print("Failed!")"""
	
	print("\nCongrats on passing the RSA Pop Quiz! Here is your flag:",flag)

if __name__ == "__main__":
	main()
