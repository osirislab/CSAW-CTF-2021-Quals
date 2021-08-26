#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void final_password(){
        char second_input[16] = {0};
        printf("Now can you guess the final password?\n");
	getchar();
        gets(second_input);
        printf("Sorry! %s is not correct!\n", second_input);
        puts("Goodbye!");
}

/*
int second_password(unsigned long last_input){
	int rem;
	for(int i = 5; i <=10; i++){
		last_input = (last_input - 19) * 11+i;
		rem = last_input % 3;
		last_input = last_input/(rem+48);
		last_input = last_input + (rem*27);
		if((last_input) == 368934881474191083){
			puts("That is correct!\n");
			final_password();
			return 110;
		}
	}
	puts("Sorry! That is not correct!\nGoodbye!\n");
	return -1;
}
*/

int second_password(unsigned long input){

	int one = input % (input - 3458713659);
	int two = input % 3;
	int three = input / (((input % 100) * 2) - 1);
	int four = input % 12;
	int seven = input % 10;
	int ten = 827;
 

	if (one == 345,437,819 && two == 2 && three == 77006959 && four == (input % four) + 3 && seven == 7 && ten == (input % 1000)) {
	final_password();
	return 110;
	}

	puts("Sorry! That is not correct!\nGoodbye!\n");
	return -1;
}


void print_flag(){
	FILE *fp;
	char contents [136];

	puts("Here is your flag: ");
	fp = fopen("flag.txt", "r");
	if(fp==NULL){
		puts("If you see this, try your exploit locally, or contact an administrator");
	}
	else{
		fgets(contents, 16, fp);
		printf("%s", contents);
	}
}


int main() {
	int first_input;
	long first_password;
	unsigned long last_input;

	printf("Please enter the first password\n");
	scanf(" %d", &first_input);
	first_password = rand();

	if(first_input == first_password){
		printf("Correct!\n");
		getchar();
		puts("Please enter the second password");
	        scanf(" %d", &last_input);
		if(last_input > 2000000000){
			second_password(last_input);
		}
		return -1;
	}
	printf("Sorry! That is incorrect\nGoodbye!\n");
	return -1;
	return 0;
}
