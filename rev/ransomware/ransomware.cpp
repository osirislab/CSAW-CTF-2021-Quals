#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>

/*
 *  Check host for infection
 */
bool check_host(){
    return true;
}

/*
 *  Gather system information
 */
void enumerate_system(char* buffer, int buffer_length){
    return;
}

/*
 *  Check if system is in target list
 */
bool check_system(){
    char* system_info = (char*)malloc(100);
    enumerate_system(system_info, 100);
    return true;
}

/*
 *  Iterate through directory and encrypt all files
 */
bool encrypt_directory(){
    return;
}

/*
 *  Create file to mark host as infected
 */ 
bool mark_infected(){
    return true;
}

/*
 *  Establish C2 Connection
 */
bool c2_connect(){
    return true;
}

/*
 *  Executes business flow of Ransomware
 */
int main(int argc, const char** argv){

    // Check if host is already infected 
    bool is_infected = check_host();
    
    // Gather system information
    bool valid_system = check_system();

    // Attempt C2 Connection
    if (!c2_connect){
        // If not infected + unix system then execute
        if (!is_infected && valid_system){

            // Execute ransomware
            if (!encrypt_directory()){
                // Maybe delete self if encryption fails?
                exit(1);
            }

            // Create a unique file to mark system as infected
            if (!mark_infected()){
                // Not sure if we should check or what to do if marking is not possible
                exit(1);            
            }
        }
    }

    return 0;
}