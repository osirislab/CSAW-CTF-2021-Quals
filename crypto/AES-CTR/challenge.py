from Crypto.Cipher import AES
from Crypto.Util import Counter
import os

KEY = os.urandom(16)

def encrypt(plaintext):
	cipher = AES.new(KEY, AES.MODE_CTR, counter=Counter.new(128))
	ciphertext = cipher.encrypt(plaintext)
	return ciphertext.hex()

with open('quote.txt', 'rb') as f:
	quote = f.read()
e_q = encrypt(quote)

with open('flag.txt', 'rb') as f:
	flag = f.read()
e_f = encrypt(flag)

with open('encrypt.txt','w') as f:
	f.write(f'Quote: {e_q}\n')
	f.write(f'Flag: {e_f}\n')
