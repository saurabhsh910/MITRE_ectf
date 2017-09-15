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

/*
 * Functions for managing secrets.
 */

#include "secret_management.h"
#include <stdint.h>

/* This is a storage location for metadata RX'd from last successful FW update. */
union fw_metadata fw_metadata SECRETVAULT __attribute__((aligned(0x100))) = {
    .fw_version = 1,
    .fw_size = 0,
    .fw_signature = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .fw_random_seed = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .fw_debug = 0
};

// Write firmware metadata to secret vault
// Note: writes must be page aligned, so union makes sure this is true.
void write_fw_metadata_to_vault(uint16_t new_size, uint16_t new_version, uint8_t *new_signature, uint8_t *new_rand_seed, uint16_t new_debug_flag)
{
    union fw_metadata new_fw_metadata;
    uint_farptr_t current_metadata_ptr = pgm_get_far_address(fw_metadata);

    // Stage updates
    new_fw_metadata.fw_size = new_size;
    new_fw_metadata.fw_version = new_version;
    //memcpy(&new_fw_metadata.fw_size, &new_size, 2);
    //memcpy(&new_fw_metadata.fw_version, &new_version, 2);
    memcpy(&new_fw_metadata.fw_random_seed[0], new_rand_seed, RANDOM_SEED_SIZE_BYTES);
    memcpy(&new_fw_metadata.fw_signature[0], new_signature, SHA1_HASH_SIZE_BYTES);
    new_fw_metadata.fw_debug = new_debug_flag;

    // Write updates
    program_flash(current_metadata_ptr, (unsigned char *) &new_fw_metadata);
}

/* 
uint16_t get_fw_version(void) {

    return pgm_read_word_far(pgm_get_far_address(fw_metadata) + offsetof(union fw_metadata, fw_version));
   
}

uint16_t get_fw_size(void) {

    return pgm_read_word_far(pgm_get_far_address(fw_metadata) + offsetof(union fw_metadata, fw_size));
   
}

void get_fw_signature(uint8_t *sig_buff) {

    uint_farptr_t current_signature_ptr = (pgm_get_far_address(fw_metadata) + offsetof(union fw_metadata, fw_signature));
    memcpy_PF(sig_buff, current_signature_ptr, SHA1_HASH_SIZE_BYTES);

}

void get_fw_rand(uint8_t *rand_buff) {

    uint_farptr_t current_random_ptr = (current_metadata_ptr + offsetof(union fw_metadata, fw_random_seed));
    memcpy_PF(rand_buff, current_random_ptr, RANDOM_SEED_SIZE_BYTES);

}
*/





