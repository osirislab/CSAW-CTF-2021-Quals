# Author
name: n132(Xiang Mei)
mail: xm2146@nyu.edu
time: 25/07/2021 8:10AM GMT+8
# Comments:
1. `second_password` should be complex enough for the human being: angr is good at dealing with linear path exploration, while a human cannot handle a large number of irregular jumps. And you can find some interesting tricks on https://github.com/jakespringer/angr_ctf.
2. `print_flag` uses `fgets(s, 16, stream)` which can't print the whole flag if the length of the flag is larger than 16. 
3. 1st and 3rd part is friendly to the beginners and can teach the knowledge related to `rand` and `stack overflow`. Please make sure this challenge's env is well configured because challengers can get a shell from this one(Ignore this comment if all the pwn challenges are deployed by some well-designed tools, such as xinetd-ctf). 

# PoC
If the purpose of `second_password` is teaching the challengers to use some SMT solvers, such as z3 and angr, you should make sure this part is complex enough for the human being.
However, I can crack this part:
```
#include<stdio.h>
int main()
{
		unsigned long last_input=0;
		unsigned long rem=0;
		for(unsigned long p=0;p!=0xffffffffffffffff;p++){
			last_input=p;
			for(int i = 5; i <=10; i++){
				last_input = (last_input - 19) * 11+i;
				rem = last_input % 3;
				last_input = last_input/(rem+48);
				last_input = last_input + (rem*27);
				if((last_input) == 368934881474191083){
					puts("That is correct!\n");
				printf("%u\t\t%u\n",p,i);
				getchar();
				}
		}
		}
}
```
Here is the log, which shows challengers could pass this part by cracking or luck(there is plenty of numbers that can pass the check).
```
###log for poc##
➜  /casw ./poc
That is correct!

5		5

That is correct!

45		6

That is correct!

48		6
...


##log for gdb ##
➜  /casw ./passwords
Please enter the first password
1804289383
Correct!
Please enter the second password
5
That is correct!

Now can you guess the final password?
eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
Sorry! eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee is not correct!
Goodbye!
[1]    471 segmentation fault  ./passwords
➜  /casw
```