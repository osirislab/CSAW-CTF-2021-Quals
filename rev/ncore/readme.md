## The Challenge
We can only give them the compiled version, it _might_ be a bit too hard, but it's (the VVP format) really a fairly simple textual format with documentation on ICARUS and they can piece together what's happening. We _can_ give them the verilog file, but it might be _too easy_ then. Also we must rate-limit somehow, I guess. <br>
The main challenge is that the memory ops only support _direct_ accessing, so imagine you have a for loop to read bytes, "R0 <- MEM(i)" looping over i, you cannot put i in a regsiter and increment because in a move instructions you have to specify the address explicitly, i.e. "R0 <- MEM(0)" where the 0 is encoded into the instructions. The solution to this challenge is that well, as it is in Von Neumann architecture, data and instructions live in harmony and well you can have self-modifying code: make a "R0 <- MEM(0)" instruction and then overwrite that 0 with 1, 2,.. as much as you want to loop. <br>
## Icarus Verilog
see here: http://iverilog.icarus.com/
compile and run like this (the flag is for SystemVeriog support):
```bash
iverilog -g2012 -o nco ncore_tb.v
vvp nco
```
## ISA
It's SUPER tiny, so you can just see the code and get what's happening, but here we go: every instruction is 2 bytes. There are 4 32bit registers. There is a 256 byte ram and program execution starts from address 0. <br>
ADD/SUB/AND/OR (only AND, SUB actually implemented): < OPCODE(3:0) | OP1(5:4) | OP2(7:6) > | < OP3(1:0) > <br>
OPi are registers. These instructions do: OP1 <- OP2 op OP3 <br>
MOVF/MOVT, (MOVE FROM/TO MEMORY): < OPCODE(3:0) | OP1(5:4) > | < ADDR(7:0) > <br>
OP1 is the destination register, OP1 <- MEM(ADDR) <br>
