#from gmpy2 import divm, mpz, mul, powmod
#import sys

import numpy as np
import sys
import logging
from ntru.ntrucipher import NtruCipher
from ntru.mathutils import random_poly
from sympy.abc import x
from sympy import ZZ, Poly
import math

#import SECRET

#key material
#n = 104525132490556452593202847360958867443850727021139374664119771884926217842051539965479047872905144890766357397753662519890618428457072902974515214064289896674717388849969373481670774897894594962128470900125169816586277785525675183392237296768481956391496477386266086799764706674035243519651786099303959008271
#e = 65537
#d = SECRET.d

priv_key_file = "myKey.priv.npz"
pub_key_file = "myKey.pub.npz"
input_file = "flag.txt"
log = logging.getLogger("ntru")

#n = 167
#p = 3
#q = 128

def encrypt_command(data):
    #with open(input_file, 'rb') as file:
    #    input = file.read()
    input_arr = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    input_arr = np.trim_zeros(input_arr, 'b')
    log.info("POLYNOMIAL DEGREE: {}".format(max(0, len(input_arr) - 1)))
    log.debug("BINARY: {}".format(input_arr))
    log.info("About to call encrypt")
    output = encrypt(pub_key_file, input_arr, bin_output=True, block=False)
    log.info("In sign: generated output. Writing to stdout. ")
    output = np.packbits(np.array(output).astype(np.int)).tobytes().hex()
    #print("output class = " + str(output.__class__))
    #print("output = " + str(output))
    #print("as hex that is " + output.hex())
    return output

# Make sure the ciphertext decrypts to the spell.
def verify(data, ct):
    print("In verify")
    return data == decrypt_command(ct)
    #return int(data.hex(), 16) == pow(int(sig.hex(), 16), e, n)

def decrypt_command(data):
    #with open(input_file, 'rb') as file:
    #    input = file.read()
    print("In decrypt_command")
    print("data = " + str(data))
    data = bytes.fromhex(data)
    print("data is now " + str(data))
    input_arr = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    input_arr = np.trim_zeros(input_arr, 'b')
    log.info("POLYNOMIAL DEGREE: {}".format(max(0, len(input_arr) - 1)))
    log.debug("BINARY: {}".format(input_arr))
    log.info("About to call decrypt")
    output = decrypt(priv_key_file, input_arr, bin_input=True, block=False)
    # def decrypt(priv_key_file, input_arr, bin_input=False, block=False):
    log.info("In decrypt_command: generated output. Writing to stdout. ")
    output = np.packbits(np.array(output).astype(np.int)).tobytes().hex()
    print("output class = " + str(output.__class__))
    print("output = " + str(output))
    output = bytes.fromhex(output)
    print("as a string that is " + str(output))
    return output


def encrypt(pub_key_file, input_arr, bin_output=False, block=False):
    log.info("Just called encrypt.")
    log.info("pub_key_file = " + str(pub_key_file))
    log.info("input_arr = " + str(input_arr))
    log.info("bin_output = " + str(bin_output))
    log.info("block = " + str(block))
    pub_key = np.load(pub_key_file, allow_pickle=True)
    ntru = NtruCipher(int(pub_key['N']), int(pub_key['p']), int(pub_key['q']))
    ntru.h_poly = Poly(pub_key['h'].astype(np.int)[::-1], x).set_domain(ZZ)
    if not block:
        if ntru.N < len(input_arr):
            raise Exception("Input is too large for current N")
        output = (ntru.encrypt(Poly(input_arr[::-1], x).set_domain(ZZ),
                               random_poly(ntru.N, int(math.sqrt(ntru.q)))).all_coeffs()[::-1])
        print("In encrypt: output = " + str(output))
    else:
        log.info("In encrypt: about to pad. Input_arr = " + input_arr)
        input_arr = padding_encode(input_arr, ntru.N)
        input_arr = input_arr.reshape((-1, ntru.N))
        output = np.array([])
        block_count = input_arr.shape[0]
        for i, b in enumerate(input_arr, start=1):
            log.info("Processing block {} out of {}".format(i, block_count))
            next_output = (ntru.encrypt(Poly(b[::-1], x).set_domain(ZZ),
                                        random_poly(ntru.N, int(math.sqrt(ntru.q)))).all_coeffs()[::-1])
            if len(next_output) < ntru.N:
                next_output = np.pad(next_output, (0, ntru.N - len(next_output)), 'constant')
            output = np.concatenate((output, next_output))

    if bin_output:
        k = int(math.log2(ntru.q))
        output = [[0 if c == '0' else 1 for c in np.binary_repr(n, width=k)] for n in output]
    return np.array(output).flatten()

def decrypt(priv_key_file, input_arr, bin_input=False, block=False):
    priv_key = np.load(priv_key_file, allow_pickle=True)
    ntru = NtruCipher(int(priv_key['N']), int(priv_key['p']), int(priv_key['q']))
    ntru.f_poly = Poly(priv_key['f'].astype(np.int)[::-1], x).set_domain(ZZ)
    ntru.f_p_poly = Poly(priv_key['f_p'].astype(np.int)[::-1], x).set_domain(ZZ)

    if bin_input:
        k = int(math.log2(ntru.q))
        pad = k - len(input_arr) % k
        if pad == k:
            pad = 0
        input_arr = np.array([int("".join(n.astype(str)), 2) for n in
                              np.pad(np.array(input_arr), (0, pad), 'constant').reshape((-1, k))])
    if not block:
        if ntru.N < len(input_arr):
            raise Exception("Input is too large for current N")
        log.info("POLYNOMIAL DEGREE: {}".format(max(0, len(input_arr) - 1)))
        return ntru.decrypt(Poly(input_arr[::-1], x).set_domain(ZZ)).all_coeffs()[::-1]

    input_arr = input_arr.reshape((-1, ntru.N))
    output = np.array([])
    block_count = input_arr.shape[0]
    for i, b in enumerate(input_arr, start=1):
        log.info("Processing block {} out of {}".format(i, block_count))
        next_output = ntru.decrypt(Poly(b[::-1], x).set_domain(ZZ)).all_coeffs()[::-1]
        if len(next_output) < ntru.N:
            next_output = np.pad(next_output, (0, ntru.N - len(next_output)), 'constant')
        output = np.concatenate((output, next_output))
    return padding_decode(output, ntru.N)


def main():
    #args = docopt(__doc__, version='NTRU v0.1')
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    #if args['--debug']:
    #    ch.setLevel(logging.DEBUG)
    #elif args['--verbose']:
    ch.setLevel(logging.INFO)
    #ch.setLevel(logging.WARN)
    #else:
    #ch.setLevel(logging.WARN)
    root.addHandler(ch)
    #log.info("Test log message")

    #log.debug(args)
    poly_input = False # bool(args['--poly-input'])
    poly_output = False # bool(args['--poly-output'])
    block = False # bool(args['--block'])
    input_arr, output = None, None
    
    '''
    if True: # not args['gen']:
        #if args['FILE'] is None or args['FILE'] == '-':
        #    input = sys.stdin.read() if poly_input else sys.stdin.buffer.read()
        #else:
        with open(input_file, 'rb') as file:
            input = file.read()
        log.info("---INPUT---")
        log.info(input)
        log.info("-----------")
        if poly_input:
            input_arr = np.array(eval(input))
        else:
            input_arr = np.unpackbits(np.frombuffer(input, dtype=np.uint8))
        input_arr = np.trim_zeros(input_arr, 'b')
        log.info("Input array: " + str(input_arr))
        #print(str(input_arr))
        #print(str(len(input_arr)))
        log.info("POLYNOMIAL DEGREE: {}".format(max(0, len(input_arr) - 1)))
        log.debug("BINARY: {}".format(input_arr))
    '''

    #print("NTRU as a Service - NaaS")
    #print("Unlimited spell slots with a 3-year subscription!\n")

    #print("Send us your spell and its encrypted version and we will cast it for you.\n")

    print("encrypt <spell>")
    print("cast <ciphertext> <spell>")
    #print("\\\\")
    #data = b"flag{t35t_fl4g}"
    #data = b"test"
    #ct = encrypt_command(data)
    #print("ct = " + ct)
    
    #print("Decrypting...")
    #verified = verify(data, ct)
    #print("verified = " + str(verified))
    
    while True:
        parts = sys.stdin.readline()[:-1].split(" ")

        try:
            if parts[0] == "encrypt":
                print("In encrypt loop...")
                print("parts[1] = " + str(parts[1]))
                print(" which has class " + str(parts[1].__class__))
                print(" and length " + str(len(parts[1])))
                spell = parts[1]#bytes.fromhex(parts[1])
                print("spell = " + spell)
                spell = bytes.fromhex(spell)
                #if spell.find(b"cat flag.txt") != -1:
                #    raise Exception()
                print(encrypt_command(bytes.fromhex(spell)))
                #print("{}".format(hex(encrypt(spell))[2:]))
            elif parts[0] == "cast":
                ct = bytes.fromhex(parts[1])
                spell = bytes.fromhex(parts[2])

                # The ciphertext must decrypt to the spell
                if not verify(spell, ct):
                    raise Exception()

                if spell == b"cat flag.txt":
                    # The signature the user sends the server can't match that produced by the server when encrypting "cat flag.txt"
                    if encrypt_command(spell) == ct:
                        print("Hey, you tried to cast a forbidden spell.")
                        raise Exception()
                    else:
                        print("Something just appeared out of nowhere!")
                        with open("flag") as file:
                            print("".join(file.readlines()))
                else:
                    print("You cast your spell! It does nothing :(")
            elif parts[0] in ["quit", "exit"]:
                print("Vanishing!")
                return
            else:
                raise Exception()
        except:
            print("Incorrect amount of magic focus...")
            print("...try again?")
    
if __name__ == "__main__":
    #test_str = b"this is not the string you're looking for"
    #if not verify(test_str, bytes.fromhex(hex(sign(test_str))[2:])):
    #    raise Exception()
    main()
