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
- From Rootkits and Bootkits: Reversing Modern Malware and Next Generation Threats, p. 211:
  "TorrentLocker: A Fatal Flaw
   Not all early ransomware was this impenetrable, due to flaws in the implementation of the encryption process. The early versions of Torrentlocker, for instance, used an Advanced Encryption standard (AES) cipher in counter mode to encrypt files. In counter mode, the AES cipher generates a sequence of key characters, which is then XORed with the contents of the file to encrypt it. The weakness of this approach is that it yields the same key sequence for the same key and initialization value, regardless of the contents of the file. To recover the key sequence, a victim can XOR an encrypted file with the corresponding original version and then use this sequence to decrypt other files. After this discovery, TorrentLocker was updated to use the AES cipher in cipher block chaining (CBC) mode, eliminating the weakness. In CBC mode, before being encrypted, a plaintext block is XORed with the ciphertext block from the previous encryption iteration so that even a small difference in input data results in a significant difference in the encrypted result. This renders the data recovery approach against TorrentLocker ineffective."
