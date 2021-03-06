# A first look at the challenge

Upon inspection of the source code, we see that we can obtain an encrypted version of the flag, encrypted with the shared secret of a Diffie-Hellman key exchange. What's special about this key exchange, is that instead of the usual $\mathbb{F}_p^*$, we're now working in the group $(\mathbb{Z}/n\mathbb{Z})^*$ with \begin{align}n &= pq\newline p &\equiv 3 \pmod 4\newline q &\equiv 3 \pmod 4\newline p, q &\text{ prime},\end{align} which implies among others that there is no generator $g$ that generates the entire group.

Furthermore, the challenge provides us with an oracle that reveals the $123$rd MSB to us. While we will see later on how exactly the group is backdoored such that this oracle can even exist, and we will actually be able to abuse this to find the solution at some point, we will also cover a *proper* solution, that does not depend on the practical existence of this oracle and that would serve as a practical proof of the bit-hardness of the $123$rd MSB for the discrete log in the group $(\mathbb{Z}/n\mathbb{Z})^*$ that can be easily extended to most other bits.

Starting communication with the server, and some quick utility functions:

```py
import os; os.environ["PWNLIB_NOTERM"] = "1" # for tqdm this time
from pwn import *
import tqdm
from json import loads, dumps
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
import hashlib
from sage.all import GF, discrete_log, crt, sqrt, ZZ


if args.LOCAL:
    io = process(["./target/release/hardcore"])
else:
    io = remote(args.HOST, args.PORT)

io.recvuntil(b"N = ")
n = int(io.recvline())
g = int(io.recvline().split(b" = ")[1])
pub = int(io.recvline().split(b" = ")[1])
alice = int(io.recvline().split(b" = ")[1])
nbits = int(io.recvline().split(b" = ")[1])
FLAG = bytes.fromhex(io.recvline().split(b" = ")[1].strip().decode())

# Convert so that LSB is at index 0
index = nbits - 123

# Once we obtain the private key, we can decrypt the flag
def dec(d):
    shared = pow(alice, d, n)
    key = hashlib.sha256(str(shared).encode()).digest()
    cipher = AES.new(key, AES.MODE_CTR, nonce=bytes(12))
    try:
        return cipher.decrypt(FLAG).decode()
    except Exception as e:
        return str(e)

# Query the oracle for point P, by default fail hard if it's not a point generated by `g`
def has(P, fail=True):
    io.sendline(str(P).encode())
    res = int(io.recvline())
    if fail:
        assert res in [0,1]
    return {1: True, 0: False, -1: None}[res]
```

---

# Recovering low bits

Given the public information $g$, $g^d \mod n$ and the challenge oracle, we will first proceed to recover all less significant bits than the one the oracle can reveal to us. When the number of more significant bits would be lower than it is in this challenge (or when you're willing to spend plenty of CPU time on this challenge), this would be sufficient to mount an attack with e.g. the baby-step-giant-step algorithm to retrieve the rest of the private key $d$ in $\tilde{\mathcal{O}}(\sqrt{2^\ell})$, where $\ell$ represents the number of more significant bits.

One of the key observations is that given $g^d$ we can easily compute $g^{d + a}$ and $g^{d - a}$, without any knowledge of $d$. In particular this allows us to set a bit we know is unset, or clear it when we know it is set.

```py
def setbit(P, i):
    return (P * pow(g, 1 << i, n)) % n

def clearbit(P, i):
    # requires modern enough python 3 for the negative exponent, use modular inverse otherwise
    return (P * pow(g, -(1 << i), n)) % n
```

Then, noting how (binary) addition works with overflow, we see that adding a single bit at position $i$, will change a bit sequence of the form `011..1` (with the least significant $1$ at position $i$), into `100...0` without changing any other bits. So, when we arrange our input $g^{d'}$ into the oracle such that position $123$ contains a $0$, and every bit from there until the position $\alpha$ we're looking at contains a $1$ (we can easily do this inductively by first determining the bit and setting it when needed), we know that the bit at $\alpha$ contains a one if and only if the oracle responds with $1$ for the input $g^{d' + 2^\alpha}$.

```py
# Quick and dirty global variable
d = 0
def set(i):
    global d
    d |= (1 << i)

def right_bits(P, i):
    if has(P):
        set(i)
        P = clearbit(P, i)
    for j in tqdm.tqdm(range(i - 1, -1, -1)):
        if has(setbit(P, j)):
            set(j)
        else:
            P = setbit(P, j)
    return P
```

---

# Let's factor

At this point, we'd like to be able to somehow *slide* the more significant bits into the view the oracle offers us. If we could take a square root mod $n$, and distinguish whether it is the *principal square root*, i.e. the one that corresponds to $g^{\frac{d}{2}}$, this would be achievable. Unfortunately, taking a square root mod $n$ turns out to be as hard as factoring $n$ when $n$ is not a prime power.

Therefore, we will first apply our newfound power to find a good amount of least significant bits to factor $n$, before we continue on that road.

By Euler's theorem, we know that $g^{\varphi(n)} \equiv 1 \pmod n$ and thus we can see that $g^{n} \equiv g^{\varphi(n)} g^{n - \varphi(n)} \equiv g^{n - \varphi(n)} \pmod n$. We know that $n = pq$, so $\varphi(n) = (p - 1)(q - 1) = n - p - q + 1$. When we make the simple assumption that $p + q - 1$ is "small enough", i.e. has less bits than we can discover by our `right_bits` function from before, we can factor $n$ by the usual techniques, since we have 2 independent equations in 2 variables.

```py
from Crypto.PublicKey import RSA

right_bits(pow(g, n, n), index)
order = n - d
assert pow(g, order, n) == 1

# Ugly hack so I don't have to implement the factorization myself :)
p = RSA.construct((n, 0x10001, pow(0x10001, -1, order_multiple))).p
assert n % p == 0 and n != p
q = n // p

# Reset d, don't reuse the stuff from `n - order`
d = 0
```

---

# A first solution

Now that we've successfully factored $n$, we are actually already able to find the secret $d$ without explicitely recovering the high bits as we planned to initially. This is however only due to the presence of the backdoor in the discrete log problem that had to be introduced in the secret sauce in order to construct the bit oracle (recall that this entire challenge is essentially a proof of the bit-hardness of the discrete log, so it would not make sense to have an oracle without some weakness introduced into the group).

In order to construct a backdoor-DLP group, what can be done is this: choose two primes $p$ and $q$ such that $p-1$ and $q - 1$ are both $B$-smooth, for some appropriate bound $B$. This means that with knowledge of these primes, and potentially the factorization of $p-1$ and $q - 1$, which would form the secret trapdoor, we can calculate a discrete log in time $\tilde{\mathcal{O}}(\sqrt{B}\frac{\log p}{\log B})$. To see this, observe that we can calculate the discrete log mod $p$ and $q$ individually with the Pohlig-Hellman algorithm, which runs in time $\tilde{\mathcal{O}}(\sqrt{B})$ per prime factor, and then combine these two results with the chinese remainder theorem. Of course, introducing this weakness also opens up $n$ to Pollard's $p - 1$ algorithm.
This generally allows us to factor in time $\tilde{\mathcal{O}}(B \log^2(n))$, if $p - 1$ is *powersmooth*.
We did introduce some extra countermeasures into our construction to prevent this from happening, by making $p - 1 = 2p_0^{16}p_1$ (and similarly for $q - 1$).
This means that either of two things need to happen in order to successfully factor with a pollard $p - 1$ variant (within reasonable time): either a player needs to guess this fact, enumerating primes up to $B = 2^{30}$, but taking powers up to $B^{16}$ or higher, or applying the variant where $B'!$ is used for $B' = 16B$ as an exponent, leading to a seriously higher running time.
Given that we have at least a quadratic advantage in our discrete logarithm compared to factoring, and including some extra safety measures, we deem this approach safe enough for our purposes.

Given that the trapdoor has now been found by our solution-in-progress, we can apply the Pohlig-Hellman approach ourselves, and solve the challenge. Unfortunately, we have to rely on a technicality of the challenge implementation, so it is not quite satisfying yet.

```py
from sage.all import GF, discrete_log, crt, sqrt, ZZ
dl_p = discrete_log(GF(p)(pub), GF(p)(g))
dl_q = discrete_log(GF(q)(pub), GF(q)(g))
private = int(crt([dl_p, dl_q], [p - 1, q - 1]))
print(dec(private))
```

---

# Recovering high bits

Returning to the full solution that doesn't depend on implementation details, we again start looking at finding principal square roots of $g^d$.

We want to find *the* square root of $g^d$ that corresponds to $g^{\frac{g}{2}}$ (this also still requires setting the LSB to $0$ to ensure $g^d$ is actually a quadratic residue). To get started, we first make sure we can find all modular square roots of $g^d$ and afterwards, we will use our established abilities to verify which of these is the principal square root. Once we have identified that, it's only a matter of "shifting" the current $d$ to the right, and repeating these steps until all high bits have been found.

To find square roots $\mod pq$, we can find the square roots $\mod p$ and $\mod q$ individually, and combine them pairwise with the chinese remainder theorem. Because $(\mathbb{Z}/n\mathbb{Z})^*$ is not a cyclic group, and $g$ only generates half of the elements in the group, only 2 out of the 4 possible square roots will have a discrete log. To identify which of those two corresponds to the shift of $d$, we can use our old approach to identify if everything to the right of the oracle bit is still set to $1$, which will only be preserved for the square root where a shift happens.

```py
def left_bits(P, idx):
    for i in tqdm.trange(idx + 1, nbits):
        P = setbit(clearbit(P, 0), idx) # Clear LSB -> make square; make the current bit part of the 1 sled before shifting
        for ss in [crt([ZZ(x), ZZ(y)], [p, q]) for x in sqrt(GF(p)(P), all=True) for y in sqrt(GF(q)(P), all=True)]:
            candidate_bit = has(ss, fail=False)
            if candidate_bit is None: continue
            if candidate_bit:
                Q = clearbit(ss, idx)
            else:
                Q = ss
            if has(setbit(Q, 0)): # see if it flows all the way over the 1s
                P = Q
                if candidate_bit:
                    set(i)
                break
        else:
            raise RuntimeError("Could not find a good square root")
```

If we had less missing bits, an alternative approach to recovering the high bits --- not depending on the factorization of $n$ --- could be constructed from a variant of Shanks' Baby-Step Giant-Step algorithm, in time $\tilde{\mathcal{O}}\left(2^{\mathsf{index}/2}\right)$.

---

# Putting it all together

With all prerequisites out of the way, it's simply a matter of applying it to find the full solution.

```py
d = 0
P = right_bits(pub, index)
left_bits(P, index)
print(dec(d))
```

---

# One potential problem

One thing this writeup neglected so far is the possibility for `right_bits` to go wrong. When $d' \ge |g|$, we would see a reduction mod $|g|$, and get invalid results. This doesn't happen in this case because it becomes unlikely that this is triggered the farther to the right the oracle lies. Should this case happen nonetheless -- and we can detect this by noticing that the discrete log is incorrect -- this would imply that the most significant bit of $d$ has to be $1$, and as such we can set it to $0$, repeat our algorithm, and set the bit back to $1$ in our final result. This modification is then guaranteed not to have this wrap around problem.
