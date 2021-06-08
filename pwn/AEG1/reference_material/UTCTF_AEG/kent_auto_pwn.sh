#!/bin/sh
template=$(cat <<- EOM
from pwn import *
context.terminal = ["urxvtc", "-e", "sh", "-c"]
context.log_level = 'debug'
e = ELF("./$1")
rop = ROP(e)
local = 1
if local:
    r = process("./$1")
else:
    r = remote("", 1234)
poprax = rop.find_gadget(["pop rax", "ret"])
padding = "i" * 100
payload = "".join([])
payload = padding + payload
if local:
    gdb.attach(r)
# r.sendline(payload)
r.interactive()
EOM
)
echo "$template" > $1.py
binaryninja $1 &
vim $1.py