# Python program to explain os.urandom() method 
          
# importing os module 
import os
import binascii
import base64
import random
import codecs
import string

flag = "flag{this-is-a-flag}"
size_of_flag = len(flag)

def rot13(s):
    rot13 = string.maketrans( 
        "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz", 
        "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm")
    return(string.translate(s, rot13))

# Using os.urandom() method to get random string
# then hide an easter egg and the flag.   Then base64 
# encode and rot-13 the string for good measure
rand_result = os.urandom(0x600)
# Output will be different everytime
hexy = binascii.hexlify(rand_result)
print(hexy)
random_number = random.randrange(0x32, (0x600 - size_of_flag+1))
full_result = 'magnet' + hexy[6:random_number] + flag + hexy[(random_number+size_of_flag):]
print(full_result)
rot13_result = rot13(full_result)
print(rot13_result)
payload = base64.b64encode(rot13_result)

# Print the random bytes string

print(payload)
payfile = open('payload.dat', 'w')
payfile.write(payload)
payfile.close()
