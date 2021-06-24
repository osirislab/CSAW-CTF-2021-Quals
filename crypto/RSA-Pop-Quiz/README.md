# RSA Pop Quiz

> Category: crypto
> Suggested Points: 500

# Description
> Detailed description as it would need to be explained to other lab members

5 different RSA attacks have to be used to crack 5 different ciphertexts

# Deployment
> Any special information about the deployment if there is a server component



# Flag

flag{}

# Solution
> As detailed as possible description of the solution. Not just the solver script. As full a description as possible of the solution for the challenge.

Part 1 --> Weiner's attack
Part 2 --> The difference between the primes is 6. Therefore, the modulus can be factorized
Part 3 --> LSB oracle. Send 2*plain, 4*plain, 8*plain, etc. to find the range in which the plaintext lies. For full details, please refer to https://bitsdeep.com/posts/attacking-rsa-for-fun-and-ctf-points-part-3/
Part 4 --> Lower half of the private key is exposed. Therefore, the entire key can be determined from that
Part 5 --> RSA CRT where dp and dq are small. There are a few papers covering this topic

# TO DO
Implement part 5
