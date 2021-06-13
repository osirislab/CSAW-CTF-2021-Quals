## Ransomware Challenge

### `Help, IR team! Our files were encrypted and a super valuable file wasn't backed up! Here is a PCAP of when the attack may have happened, our back-ups, and the encrypted files.`

### Provided Files:
- PCAP, backup directory, and encrypted directory.

### Steps to solve:
- Extract the dropper from the PCAP
- Dropper used to download the Encryptor (Downloaded outside of capture time)
- Reverse the dropper to figure out how to connect and download the encryptor. (Password? System time?)
- Reverse the encryptor to determine that AES in CTR mode was used to download files. 
- The backup and its corresponding encrypted file can be used to determine the key used to encrypt the file. 
- Decrypt the flag file using recovered key
- PROFIT

### Encryptor:
- Only encrypts PDFs? in TBD directory.
- Encrypted file names are the hash of the contents of the original file
- AES CTR mode
- Generates its own key and runs

### Reference:
- Not part of the challenge. Previous solve from HackTheBox CTF, reference material for writing the encryptor.
