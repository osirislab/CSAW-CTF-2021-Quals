# Crack Me
## Challenge: 
Can you crack this?
Your hash: A60458d2180258d47d7f7bef5236b33e86711ac926518ca4545ebf24cdc0b76c
Your salt: the encryption method of the hash

## Approach:
Your salt would be "SHA256". Use Hashcat or any hash decrypting tool to decrypt the hash. The Answer is "cathouse".
hashcat -a 0 -m 1420 A60458d2180258d47d7f7bef5236b33e86711ac926518ca4545ebf24cdc0b76c:sha256 rockyou.txt

## Todo:
We are improving the prompt for the salt. It would be better if we can make it less obvious. 

