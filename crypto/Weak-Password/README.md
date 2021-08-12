# Weak Password
## Challenge: 
Can you crack Aaron’s password hash? He seems to like simple passwords. I’m sure he’ll use his name and birthday in it. Hash: 111cbe3201371926fec860dbe9cdfcc4

## Approach:
The hint implies that the password might have "Aaron" followed by 8 digits. Use brute force mode in hashcat with rules: 
hashcat -m 0 -a 3 hash.txt Aaron?d?d?d?d?d?d?d?d

