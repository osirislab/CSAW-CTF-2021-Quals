#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>


#define CONTENTLENGTH 400
extern void *_GLOBAL_OFFSET_TABLE_;
#define PRINTF_GOT_OFFSET 4
//extern void *_DYNAMIC_;

/*
void getInput(int length, char * buffer){
    memset(buffer, 0, length);
    int count = 0;
    char c;
    while((c = getchar()) != '\n' && !feof(stdin)){
        if(count < (length-1)){
            buffer[count] = c;
            count++;
        }
    }
    buffer[count] = '\x00'; 
}
*/

void win(){
    puts("YOU WIN!! Nice job.\n");
    exit(1);
}


void runChallenge(){
    char userinput[CONTENTLENGTH];
    void ** printf_GOT;
    void * GOT_page_start;
    printf("*** Procrastination Simulator ***\n");
    printf("   I\'m writing a DOCUMENT and the deadline\'s in one minute! Give me some material to store at %p and I will print it immediately!", &userinput);
    puts("");
    fflush(stdout);
    fgets(userinput, CONTENTLENGTH, stdin);
    puts("Thanks! Adding to the final version:\n");
    printf(userinput);

    // head of the GOT, points to _DYNAMIC
    //printf("_GLOBAL_OFFSET_TABLE = %p\n", &_GLOBAL_OFFSET_TABLE_);
    printf_GOT = (&_GLOBAL_OFFSET_TABLE_)+PRINTF_GOT_OFFSET;
    // location of printf in the GOT
    //printf("_GLOBAL_OFFSET_TABLE = %p\n", printf_GOT);// + 4*sizeof(void *))); // Should be printf
    // This prints the location of printf in libc
    //printf("_GLOBAL_OFFSET_TABLE = %p\n", *printf_GOT);// + 4*sizeof(void *))); // Should be printf

    // Overwrite the pointer to printf in the GOT with null bytes. Make the memory writeable first
    GOT_page_start = (void *) ((long unsigned)(printf_GOT) - (long unsigned)(printf_GOT) % 0x1000);
    //printf("Changing memory protection at address %p\n", GOT_page_start);
    mprotect(GOT_page_start, 0x1000, PROT_READ | PROT_WRITE);
    //printf("Writing null pointer...\n");
    *printf_GOT = 0;
    //printf("Writing complete.\n");
    mprotect(GOT_page_start, 0x1000, PROT_READ);
    //printf("Memory protected.\n");

    // Future calls to printf will now seg fault.
    //printf("_GLOBAL_OFFSET_TABLE = %p\n", *printf_GOT);// + 4*sizeof(void *))); // Should be printf
    return;
}


// This is the template but we want the generator for this code to use command-line arguments to populate these fields:
// 1. DOCUMENT
int main(int argc, char **argv){
    setvbuf(stdout, NULL, _IONBF, 0);
    // TODO: Argument checking
    runChallenge();
    return 0;
}


