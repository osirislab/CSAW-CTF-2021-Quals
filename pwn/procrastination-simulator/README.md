
### AEG Basic problem

    This challenge (Automated Exploit Generation) is modeled loosely after the AEG challenge in the University of Texas CTF earlier this year, except that we use format string vulnerabilities instead of a buffer overflow exploit. 

    What we do is generate a large number of Docker containers that all have slightly different binaries running in them. The user needs the password from the previous Docker container to get the password and address of the next one. (So for testing we need to make sure they can't skip to the end and guess the password somehow.) The password is an md5 hash that is randomly generated with a seed, so it should be hard to guess. There's no time limit on how long the player can take to solve each challenge, but doing this manually would be as painful as solving a blind SQL injection manually.

    I started by creating a framework that generates the Docker containers and just gives users shell after they enter the password, and a solver that loops through the containers, "solving" the challenges until the flag at the end is revealed. Then I moved on to implementing the levels. As of the present commit, only Level One is implemented. Here's the design:

    Level 1. 32-bit binary with partial RELRO and no position-independent execution. There is a win() function in a random position and 99 decoy functions. The executable is provided with symbols. The user enters text which is echoed back to them, and then exit(0) is called. They can overwrite the pointer in exit() to jump to win(). There's a solver script.

    Level 2. 64-bit binary, otherwise the same design.

    Level 3. 64-bit binary, but they don't get symbols this time.

    Level 4. 64-bit binary, but with position-independent execution. They get two vulnerable print statements. The idea is to leak a stack address and a code address, then overwrite the return address with the address of win(). This gets trickier because occasionally the return address will have `0x0a` as its last byte. The overwrite is still doable but the code to do it will be delicate and it's less likely that there will be tools online that will solve this. Users will be forced to write their own solver code if they haven't been doing so already. 

    Questions during testing:

    1. Once we know a password, can users figure out the random seed and guess the next password in the series? How do we make sure this can't happen?
    2. Any other ways to break the chain?
    3. The current format string buffer is probably sized too generously. 

### TODO

    1. Level 2
    2. Level 3
    3. Level 4
    4. Consider making the challenge harder by adding features like the `encode` functions seen in the UTCTF challenge, or possibly a scripting challenge to solve to get to the pwnable section. (Honestly though I want to move on to an auto-ROP challenge if there's time.)
