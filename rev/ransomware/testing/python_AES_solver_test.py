
# Testing AES with CTR mode, reusing key and iv

#from Crypto.Cipher import AES
#from Crypto.Util import Counter
#import random

#key = b'Random_key123456'
#iv = b'0123456789abcdef'
bs = 1024

def xor_two_byte_strings(bs1, bs2):
    out = b''
    l = min(len(bs1), len(bs2))
    for i in range(l):
        out += bytes([(bs1[i]^bs2[i])])
    return out

xor_two_byte_strings(b'ABCDE', b'     ')

def decrypt(file1_pt, file1_ct, file2_ct, out_file):
    done = False
    while not done:
        file1_pt_chunk = file1_pt.read(1024*bs)
        file1_ct_chunk = file1_ct.read(1024*bs)
        file2_ct_chunk = file2_ct.read(1024*bs)
        if len(file1_pt_chunk) != 0 and len(file1_ct_chunk) != 0 and len(file2_ct_chunk) != 0:
            tmp = xor_two_byte_strings(xor_two_byte_strings(file1_ct_chunk, file2_ct_chunk),file1_pt_chunk)
            out_file.write(tmp)
        else:
            done=True

def decrypt_wrapper(file1_pt_filename, file1_ct_filename, file2_ct_filename, out_filename):
    with open(file1_pt_filename, 'rb') as file1_pt, \
         open(file1_ct_filename, 'rb') as file1_ct, \
         open(file2_ct_filename, 'rb') as file2_ct, \
         open(out_filename, 'wb') as out_file:
        decrypt(file1_pt, file1_ct, file2_ct, out_file)

decrypt_wrapper(file1_pt_filename="2020_IC3Report.pdf", \
                file1_ct_filename="2020_IC3Report.pdf.encryptastic", \
                file2_ct_filename="flag.pdf.encryptastic",\
                out_filename="flag.pdf.solved")


