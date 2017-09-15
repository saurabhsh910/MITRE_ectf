/*
 * Copyright 2017 Mark Horvath, Surbhi Shah, Tiemoko Ballo, Saurabh Sharma, Pouria Pezeshkian, Karthic Palaniappan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 */

#include <avr/io.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include "pgmspace.h"
#include "secret_management.h"
#include "interrupts.h"
// From AVR-Crypto-Lib
#include "aes.h"
#include "hmac-sha1.h"
#include "prng.h"

/* 2 * RANDOM_SEED_SIZE_BYTES + sizeof(tocks) + sizeof(timer1_counter) */
#define DYNAMIC_SEED_SIZE_BYTES  70
#define DYNAMIC_SEED_SIZE_BITS	(DYNAMIC_SEED_SIZE_BYTES << 3)

// Generate a pseudo random number
void rand_fill(uint8_t buffer[SHA1_HASH_SIZE_BYTES])
{
    uint_farptr_t bl_rand_seed_ptr; 
    uint_farptr_t fw_rand_seed_ptr;
    uint_farptr_t aes_key_ptr;

    uint8_t dynamic_seed[DYNAMIC_SEED_SIZE_BYTES];
    uint8_t aes_key[AES_KEY_SIZE_BYTES];
    uint32_t current_tocks;
    uint16_t current_ticks;
    uint16_t index = 0;

    bl_rand_seed_ptr = pgm_get_far_address(bl_random_seed);
    fw_rand_seed_ptr = (pgm_get_far_address(fw_metadata) + offsetof(union fw_metadata, fw_random_seed));

    // Get current uptime
    current_tocks = uptime_tocks;
    current_ticks = TCNT1;

    // Assemble dynamic seed buffer
    memcpy(&dynamic_seed[index], &current_tocks, sizeof(current_tocks));
    index += sizeof(current_tocks);

    memcpy(&dynamic_seed[index], &current_ticks, sizeof(current_ticks));
    index += sizeof(current_ticks);

    memcpy_PF(&dynamic_seed[index], bl_rand_seed_ptr, RANDOM_SEED_SIZE_BYTES);
    index += RANDOM_SEED_SIZE_BYTES;
    
    memcpy_PF(&dynamic_seed[index], fw_rand_seed_ptr, RANDOM_SEED_SIZE_BYTES);
    index += RANDOM_SEED_SIZE_BYTES;

    // Get key from secret storage 
    aes_key_ptr = pgm_get_far_address(secret_key);
    memcpy_PF(aes_key, aes_key_ptr, AES_KEY_SIZE_BYTES);

    // Compute hash of buffer
    hmac_sha1(buffer, aes_key, AES_KEY_SIZE_BITS, dynamic_seed, DYNAMIC_SEED_SIZE_BITS);

    // Zero out key 
    memset(&aes_key, 0, sizeof(aes_key));
}

// Retrive pseudo random 32-bit uint
uint32_t my_rand(void)
{
    uint32_t ret;
    uint8_t hmac_sha1_result[SHA1_HASH_SIZE_BYTES];

    rand_fill(hmac_sha1_result);

    ret  = (((uint32_t) hmac_sha1_result[0]) << 24);
    ret |= (((uint32_t) hmac_sha1_result[1]) << 16);
    ret |= (((uint32_t) hmac_sha1_result[2]) << 8);
    ret |= hmac_sha1_result[3];

    // Zero out temp space
    memset(hmac_sha1_result, 0, SHA1_HASH_SIZE_BYTES);   

    return ret;
}

// Generate pseduo random nonce
void generate_nonce(uint8_t nonce[AES_BLOCK_SIZE_BYTES])
{
    uint8_t hmac_sha1_result[SHA1_HASH_SIZE_BYTES];
    rand_fill(hmac_sha1_result);
    memcpy(nonce, hmac_sha1_result, AES_BLOCK_SIZE_BYTES);

    // Zero out temp space
    memset(hmac_sha1_result, 0, SHA1_HASH_SIZE_BYTES);   
}

