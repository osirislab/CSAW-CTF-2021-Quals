
# Testing AES with CTR mode, reusing key and iv

from Crypto.Cipher import AES
from Crypto.Util import Counter
import random

key = b'Random_key123456'
#iv = b'0123456789abcdef'


def decrypt(in_file, out_file):
    ctr = Counter.new(128)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    bs = AES.block_size
    chunk = ''
    done = False
    while not done:
        chunk = cipher.decrypt(in_file.read(1024 * bs))
        if len(chunk) != 0:
            out_file.write(chunk)
        else:
            done=True


in_filename = "flag.pdf.encryptastic"
out_filename = "flag.pdf.decrypted"

with open(in_filename, 'rb') as in_file, open(out_filename, 'wb') as out_file:
    decrypt(in_file, out_file)

in_filename = "2020_IC3Report.pdf.encryptastic"
out_filename = "2020_IC3Report.pdf.decrypted"

with open(in_filename, 'rb') as in_file, open(out_filename, 'wb') as out_file:
    decrypt(in_file, out_file)

