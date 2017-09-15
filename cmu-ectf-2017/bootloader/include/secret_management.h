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

#ifndef SECRET_MANAGEMENT_H_
#define SECRET_MANAGEMENT_H_

#include <stdint.h>
#include <string.h>
#include "sections.h"
#include "pgmspace.h"

#define UNIQUE_SERIAL_ADDR		    0x000E	// Per datasheet pg. 368
#define UNIQUE_SERIAL_BYTE_COUNT	8	    // Per datasheet pg. 368

#define AES_KEY_STORAGE_ADDR		0xFFFF 	// Need to set this!
#define AES_KEY_SIZE_BITS   		256  
#define AES_KEY_SIZE_BYTES  		32  

#define AES_IV_STORAGE_ADDR		    0xFFFF 	// Need to set this!
#define AES_IV_SIZE_BITS    		128 
#define AES_IV_SIZE_BYTES   		16

#define AES_BLOCK_SIZE_BITS  		128
#define AES_BLOCK_SIZE_BYTES   		16

#define SHA1_HASH_SIZE_BITS  		160
#define SHA1_HASH_SIZE_BYTES  		20

#define RANDOM_SEED_SIZE_BYTES      32

void program_flash(uint32_t page_address, unsigned char *data);
void write_fw_metadata_to_vault(uint16_t new_size, uint16_t new_version, uint8_t *new_signature, uint8_t *new_rand_seed, uint16_t new_debug_flag);
uint16_t get_fw_version(void);
uint16_t get_fw_size(void);
void get_fw_signature(uint8_t *sig_buff);
void get_fw_rand(uint8_t *rand_buff);

union fw_metadata 
{
    struct
    {
        uint16_t fw_version; // version number of current firmware
        uint16_t fw_size; // size of current firmware
        uint8_t fw_signature[SHA1_HASH_SIZE_BYTES]; // signature of current firmware
        uint8_t fw_random_seed[RANDOM_SEED_SIZE_BYTES]; // random seed baked into firmware
        uint16_t fw_debug; // set to 1 if zero version is installed 
    };
    
    /* Helps ensure that union is 1 page size -- Be careful if adding members
     * to the struct so we don't exceed 1 page. */
    uint8_t __page_size[SPM_PAGESIZE];
};

// Align to page boundary
extern union fw_metadata fw_metadata SECRETVAULT __attribute__((aligned(0x100)));

extern uint8_t secret_key[AES_KEY_SIZE_BYTES] SECRETVAULT;
extern uint8_t bl_random_seed[RANDOM_SEED_SIZE_BYTES] SECRETVAULT;

#endif /*  SECRET_MANAGEMENT_H_ */
