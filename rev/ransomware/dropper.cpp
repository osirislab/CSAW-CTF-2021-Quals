/*
 *  g++ -o dropper.exe dropper.cpp
 */
#include <windows.h>
#include <stdio.h>
#include <typeinfo> //typeid to identify variable types (debugging)


int main (){
    SYSTEMTIME system_time;

    GetSystemTime(&system_time);

    printf("Month: %d\nYear: %d\n", system_time.wMonth, system_time.wYear);

    if (system_time.wMonth == 6 && system_time.wYear == 2021)
        printf("It is indeed June 2021");

    return 0;
}