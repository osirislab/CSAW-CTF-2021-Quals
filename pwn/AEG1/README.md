
### AEG Basic problem

    This challenge (Automated Exploit Generation) is modeled loosely after the AEG challenge in the University of Texas CTF earlier this year, except that we use format string vulnerabilities instead of a buffer overflow exploit. Here's the original AEG challenge:

    A user gets to download a randomly-generated binary that has the following properties:

    1. User gets to populate a buffer of size 0x40 with `fgets` into the stack frame for `main`, which then calls a function `vuln` passing a pointer to the buffer as a parameter.
    2. In a `vuln` function, the contents of that buffer get manipulated with eight `encode` functions that do things like xor every string element with a byte that's hard-coded into the binary. 
    3. Still in the `vuln` function, the 0x40 bytes in the modified buffer gets copied into a buffer in the frame for `vuln` with size 0x30, allowing enough of an overrun to overwrite the saved base pointer and return address, but nothing more (64-bit architecture). 
    4. There's a `win` function that calls `exit(100)`. 

    The challenge is for a user can 'pwn' 10 binaries within the space of a minute. Each binary has a different set of `encode` functions. It's solvable by determining the "keys" to reverse each of the encode functions, or better yet by using `angr`. But the player must fully automate the exploitation process. 

    What I want to do is to use a similar approach but teach automatic exploitation of format string vulnerabilities. 

    The source code for UTCTF was released but the code for the pwnables was not. I don't know why, I suspect some work went into writing the framework for this challenge and they didn't want to release it so they could do it again.


### Approach

    I'm going to give the user the address of the return address that they want to overwrite, and not compile with PIE enabled so that the user can determine that address of `win` programmatically. Just like making the buffer overflow bigger for UTCTF's challenge would have made ROP possible and given the user shell directly with just one binary, we have to keep a user from being able to do a ret2libc to get shell. I therefore am going to use the following design elements:

    1. Leak the address of the return address from `vuln` as part of the challenge design so the user doesn't need to
    2. Use full RELRO protection so the GOT isn't writeable
    3. Do one of the following or both:
        a. Before returning from `vuln`, bounds-check the return address to make sure that we're only returning to the code section and not to `libc`
        b. Before returning from `vuln`, overwrite the GOT address for `printf` with null bytes so that the user can't return to `main` and do multiple calls to `printf`
    4. Give the user a large `printf` buffer so that they have plenty of bytes to work with

### TODO

    1. Create a simple binary with these properties
    2. Make sure I can exploit it automatically
    3. Write C code that produces ten such binaries and checks that the user runs them and has then return a unique value like 100
    4. Consider making the challenge harder by adding features like the `encode` functions for UTCTF, or possibly a scripting challenge to solve to get to the pwnable section

### UPDATE 8-14-21: 

    During testing Eddie found that it's possible to pwn the challenge by overwriting the return address from printf_positional. I decided to scrap the approach of a single binary for a more robust one: now we have a daisy chain of N binary challenges, each running in their own docker containers. Each challenge does the following:
    1. Prompts the user for a password, such that they have to pwn the previous challenge in the chain to get the new password
    2. If the proper password is given, the binary prints out a hex dump of itself. The user then can reassemble and analyze the binary from the hex dump.
    3. Runs the actual pwnable portion of the challenge. Assuming the user pwns it:
    4. The Docker container contains the password and remote address and port of the next challenge to pwn in the chain.
    5. The final Docker container contains the flag.

    The framework for this is in the "framework" folder. The example challenge just spawns a shell after giving the binary to the user. For the framework I tested that I can retrieve the binary properly and wrote a solver that runs through the boxes, gets passwords, and trivially "pwns" each box before getting the final flag. Now we can use this to write auto-buffer overflow, auto-fmt-string, auto-ROP, and auto-heap challenges.
