#include <stdio.h>
    #include <stdlib.h>

    #define PASSWORDLENGTH 33
    #define TRUE 1
    #define FALSE 0

    char* password = "1a6b6436d8cc6d6066ae9bd4ec88bc00";

    char equalArrays(char a[], char b[], int size){
        for(int i = 0; i < size; i++){
            if(a[i]!=b[i]){
                return FALSE;
            }
        }
        return TRUE;
    }

    int password_is_correct(char* user_input){
        return equalArrays(password, user_input, PASSWORDLENGTH-1);
    }

    int main(int argc, char** argv){
        puts("Welcome to the AEG challenges!");
        char user_input[PASSWORDLENGTH];
        puts("Input password to continue:");
        fflush(stdout);
        fgets(user_input, PASSWORDLENGTH, stdin);
        if (password_is_correct(user_input)){
            printf("Correct password! :)");
            fflush(stdout);
            system("/bin/sh");
        }else{
            printf("Incorrect password. :(");
        }
        return 0;
    }