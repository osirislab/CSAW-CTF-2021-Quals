# RansomwareChallenge
Ransomware CTF Challenge:

## Ransomware Behavior
[Stages]
1) Deployment
2) Installation
3) Command-and-Control (C2)
4) Destruction
5) Extortion

[Encryption]
- AES Symmetric encryption
- Crypto++ Library

## Crypto++ Documentation
https://cryptopp.com/ </br>
https://cryptopp.com/wiki/Advanced_Encryption_Standard

## Crypto++ Library Installation:
Ubuntu
-
```
# Update Repos
sudo apt-get update

# Install all libcrypto++ libraries
# Version 6 was the latest available for me you can run apt-cache search first to double check names
sudo apt-cache search libcrypto++
sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils libcrypto++6 libcrypto++6-dbg
```

Example compilation
-
```
g++ -DNDEBUG -g3 -O2 -Wall -Wextra -o cryptotest cryptotest.cpp -l:libcryptopp.a
```

Windows
-
https://www.babaei.net/blog/how-to-build-cpp-cryptographic-library-cryptopp/

## Ransomware Workflow
[Deployment]</br>
*Not done here, it is assumed that deployment was done via dropper file. Challenge file is the actual ransomware malware*

[Installation]
1) Check if already installed (eg check for a file/filetype)

[Command-and-Control]
1) Gather system information
2) Open up channel to C2 Server
3a) If connection successful - Send system information to C2 and wait for instructions
3b) If connection unsuccessful - Use built in symmetric encryption key

[Destruction]
1) If not installed + unix system then execute encryption
2) Execute encryption:
  a) Key defined then transformed 3 times
  b) Iterate through test directory
  c) AES encrypt using Key
3) Create a unique marker to show system is infected

[Extortion]
1) Output browser html page with notice of ransomware and instructions for decryption

