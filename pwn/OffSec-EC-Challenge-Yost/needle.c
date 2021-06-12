#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>

const int overall_size = 0x1000;
const int upperbounds = 0x20;
const int lowerbounds = 0x10;
//  Have mercy on them - include an easter egg
const char egg[49] = "TGJoJ3l5IGFycnEgZ2Igc3ZhcSBuIHpudGFyZyBnYiB1cnlj\0";

int main(int, char **);
void main_processor(void);
int get_random_stacks(void);
void wait_for_them_to_find_it(char**, const int , const int );
void fudge_their_number(int *, int);

int main(int argc, char **argv) {
//  This will help give them a clue as to the lightweight
//  "encryption" (ROT13 and then base64()).  Phrase is
//  "You'll need to find a magnet to help"
  printf("%s\n", egg);
  main_processor();
  exit(0);
} 

void main_processor(void)
{
  int nbr_haystacks = get_random_stacks();
  //  Start splitting up the payload into chunks, trying
  //  to give folks some puzzle pieces the till make them use commands
  //  like heap chunks and heap bins and use a useful gdb wrapper
  int splits = overall_size/nbr_haystacks;
  char *haystacks[0x100] = { '\0'};
  const int stackspread = 0x100/nbr_haystacks;
  const int distance_between_stacks = (0x100 - stackspread)/nbr_haystacks;

  //  Get the whole hayfield from a file so the data isnt in the executable
  //  Data is created by needle.py
  FILE *fp = fopen("payload.dat", "r");
  int stack = distance_between_stacks;
  for (int i=0;i<nbr_haystacks; i++) {
    bool stacked = false;
    do {
      if (!haystacks[stack]) {
        haystacks[stack] = (char *)calloc((size_t)1, (size_t)splits);
        int nbrElems = (int)fread(haystacks[stack], splits, 1, fp);
        stacked = true;
        stack = stack + distance_between_stacks;
      }
    } while (!stacked);
  }
  fclose(fp);
  int p = 0;
  while (!haystacks[p]) {
    p++;
  }
  printf("haystacks start at:\n");
  printf("%p\n", haystacks[p]);

  wait_for_them_to_find_it(haystacks, nbr_haystacks, splits);

  //  Clean up
  for (int i=0;i<nbr_haystacks; i++) {
      free(haystacks[i]);
  }

  return;
}

int get_random_stacks(void) {

  // Get random number of stacks
  srand((unsigned int)time(NULL));
  return((rand() % (upperbounds - lowerbounds)) + lowerbounds);

}

void wait_for_them_to_find_it(char **haystacks, const int nbr_haystacks, const int splits) {
  char stack_nbr[32] = {'\0'};
  char depth[32] = {'\0'};

  fputs("The needle has been hidden.\n", stdout);
  while (1) {
    fputs("Which haystack do you want to check?\n", stdout);
    fgets(stack_nbr, 32, stdin);
    int haystack = atoi(stack_nbr);
    if (haystack > (0x100)) {
      fputs("You didn't look to see how many haystacks can fit in this field!\n", stdout);
    } else if (!haystacks[haystack]) {
      fputs("You must have brought a shovel because there is no haystack there!\n", stdout);
    } else {
      fputs("How deep into the stack?\n", stdout);
      fgets(depth, 32, stdin);
      int pointer_offset = atoi(depth);
      if (pointer_offset > splits) {
        fputs("Your stacks are not that big!\n", stdout);
      } else {
        fudge_their_number(&pointer_offset, splits);
        fputs("Finding straw or steel?\n", stdout);
        for(int i=0; i<48 ; i++) {
         printf("%1.1s",(haystacks[haystack] + pointer_offset + i));
        }
        printf("\n");
      }
    }
  }
}

void fudge_their_number(int *pointer_offset, int splits) {
  int better_number = 0;

  //  Stay off the upper boundary of the chunk by 50
  if (*pointer_offset > (splits - 48)) {
    *pointer_offset = (splits - 48);
  }
}
