#from gmpy2 import divm, mpz, mul, powmod
from pwn import remote, process
import sys
import time

host = "127.0.0.1"
port = 8779

#server = remote(host, port)
server = process('python3 ./server.py', shell=True)

#key material
#n = 104525132490556452593202847360958867443850727021139374664119771884926217842051539965479047872905144890766357397753662519890618428457072902974515214064289896674717388849969373481670774897894594962128470900125169816586277785525675183392237296768481956391496477386266086799764706674035243519651786099303959008271
#e = 65537

def byte_to_int(str):
	return int(str.hex(), 16)

def hex_to_byte(hex):
	return bytes.fromhex(("0" if len(hex) % 2 else "") + hex)

def encrypt(data):
	return pow(byte_to_int(data), e, n)

def try_sign(spell):
	server.send("sign " + spell.hex() + "\n")

	line = server.recvuntil("\n").decode("utf-8")
	if line.startswith("Incorrect"):
		server.recvuntil("\n")
		return None

	#strip off \r\n
	return line[:-2].encode("utf-8")

def try_cast(spell, sig):
	server.send(" ".join(["cast", sig.hex(), spell.hex()]) + "\n")

	line = server.recvuntil("\n").decode("utf-8")
	if line.startswith("Incorrect"):
		server.recvuntil("\n")
		return False
	elif line.startswith("You"):
		return True

	#strip off \r\n
	return server.recvuntil("\n")[:-2]

class UE(BaseException):
	def __init__(self):
		pass

def main():
	spell = b"cat flag.txt"
	'''
	c = int(spell.hex(), 16)
	r = 1
	sig_c_prime = None 

	while sig_c_prime is None:
		try:
			c_prime = mul(c, powmod(r, e, n)) % n
			msg = hex_to_byte(hex(c_prime)[2:])

			if any([x in list(map(ord, [y for y in "\0 \t\r\n"])) for x in msg]):
				raise UE()
			resp = try_sign(msg)

			if resp is not None:
				sig_c_prime = int(resp, 16)
				break
		except KeyboardInterrupt:
			raise
		except UE:
			pass
		r += 1

	sig = hex( divm(sig_c_prime, r, n) )[2:]
	print("signature:", hex_to_byte(sig))
	flag = try_cast(spell, hex_to_byte(sig))
	print("FLAG:", flag)
	'''

if __name__ == "__main__":
	server.recvuntil("cast <ciphertext> <spell>\n")
	server.send("encrypt 61616161")
	server.interactive()
	print(server.recvuntil("\\\\\r\n"))
	try_str = b"hocus  pocus"
	assert(try_cast(try_str, hex_to_byte(try_sign(try_str).decode("utf-8"))))
	main()
