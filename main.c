/**
 * @file main.c
 * @author Matthew Gilpin
 * @brief A proof of concept for Spectre - CVE2017-5753
 * @version 0.1
 * @date 2023-03-12
 * 
 * @cite Spectre Attacks: Exploiting Speculative Execution
 * @link DOI 10.1109/SP.2019.00002
 * This code is heavily based off of the above paper. 
 * 
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("-- Spectre Demo for COMS4507 Semester 1 2023 --\n");
    printf("-- CVE2017-5753 --\n");

    return 0;
}


/**
 * @brief Victim code goes here
 * 
 */

uint32_t array_1_size = 16;
uint8_t  array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,16};
uint8_t  array2[256 * 512];

char *secret = "The secret COMS4507 password is :\"incorrect\"";


/**
 * End victim code.
 */