/*
 * Copyright 2017 The MITRE Corporation
 *
 * Modifications: Copywright 2017 Mark Horvath, Surbhi Shah, Tiemoko Ballo, Saurabh Sharma, Pouria Pezeshkian, Karthic Palaniappan
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
 * bootloader.c
 *
 * If Port B Pin 2 (PB2 on the protostack board) is pulled to ground the
 * bootloader will wait for data to appear on UART1 (which will be interpretted
 * as an updated firmware package).
 *
 * If the PB2 pin is NOT pulled to ground, but
 * Port B Pin 3 (PB3 on the protostack board) is pulled to ground, then the
 * bootloader will enter flash memory readback mode.
 *
 * If NEITHER of these pins are pulled to ground, then the bootloader will
 * execute the application from flash.
 *
 * If data is sent on UART for an update, the bootloader will expect that data
 * to be sent in frames. A frame consists of two sections:
 * 1. Two bytes for the length of the data section
 * 2. A data section of length defined in the length section
 *
 * [ 0x02 ]  [ variable ]
 * ----------------------
 * |  Length |  Data... |
 *
 * Frames are stored in an intermediate buffer until a complete page has been
 * sent, at which point the page is written to flash. See program_flash() for
 * information on the process of programming the flash memory. Note that if no
 * frame is received after 2 seconds, the bootloader will time out and reset.
 *
 */

#include <avr/io.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <util/delay.h>
#include "uart.h"
#include <avr/boot.h>
#include <avr/wdt.h>
#include <avr/interrupt.h>
#include "pgmspace.h"
#include "secret_management.h"
#include "sections.h"
#include "interrupts.h"
#include "prng.h"

// From AVR-Crypto-Lib
#include "aes.h"
#include "bcal_aes256.h"
#include "bcal-cbc.h"
#include "sha1.h"
#include "hmac-sha1.h"

#define OK          ((unsigned char)0x00)
#define ERROR       ((unsigned char)0x01)
#define APP_START_ADDR   0x2f00
#define RELEASE_MSG_ADDR 0xb100 // 0x2f00 + 30*1024 (Max size of firmware) + 10*256 (Keeping release message 10 pages apart)
#define RELEASE_MSG_MAX_SIZE 1024
//#define STAGING_START_ADDR   (RELEASE_MSG_ADDR + RELEASE_MSG_MAX_SIZE + 2560)
#define DELAY_MAX 50000

/* IVR || (((nonce || IVF || START_ADDR || SIZE) || HMAC) || PAD)) EncIVR 
 *  16        16       16     4             4       20       4             */
#define RESPONSE_SIZE_BYTES             80 // 5 blocks (4 bytes padding at end)
#define RESPONSE_OFFSET_NONCE           0
#define RESPONSE_OFFSET_IVF             (RESPONSE_OFFSET_NONCE + AES_BLOCK_SIZE_BYTES)
#define RESPONSE_OFFSET_START_ADDR      (RESPONSE_OFFSET_IVF + AES_IV_SIZE_BYTES)
#define RESPONSE_OFFSET_SIZE            (RESPONSE_OFFSET_START_ADDR + 4)

#define TX_ADDRESS_SIZE_BYTES           4
#define TX_PAYLOAD_SIZE_BYTES           SPM_PAGESIZE
#define TX_SIGNATURE_SIZE_BYTES         SHA1_HASH_SIZE_BYTES
#define TX_PADDING_SIZE_BYTES           8
#define TX_TOTAL_SIZE_BYTES             (TX_ADDRESS_SIZE_BYTES + TX_PAYLOAD_SIZE_BYTES + TX_SIGNATURE_SIZE_BYTES + TX_PADDING_SIZE_BYTES)

#define TX_OFFSET_ADDRESS               0
#define TX_OFFSET_PAYLOAD               (TX_OFFSET_ADDRESS + TX_ADDRESS_SIZE_BYTES)
#define TX_OFFSET_SIGNATURE             (TX_OFFSET_PAYLOAD + TX_PAYLOAD_SIZE_BYTES)
#define TX_OFFSET_PADDING               (TX_OFFSET_SIGNATURE + TX_SIGNATURE_SIZE_BYTES)

#define PAGE_ALIGN_MASK                 ((uint32_t) ~(SPM_PAGESIZE - 1UL))
#define MAX_ALLOWABLE_FIRMWARE_SIZE     30720  // Assuming (1024 bytes/kb) * 30 kb
#define VERSION_OFFSET                  2  // Version takes up 2 bytes 

#define FINAL_FRAME_SIZE_BYTES          64
#define FINAL_PAYLOAD_SIZE_BYTES        44
#define FINAL_PAYLOAD_SIZE_BITS         (FINAL_PAYLOAD_SIZE_BYTES * 8)

void load_firmware(void);
void readback(void) BOOTLOADERFUNCS;
void boot_firmware(void) BOOTLOADERFUNCS;

// Anti-glitch delay vars
uint32_t delay;
volatile uint32_t overflow_counter;

const char delay_str[] PROGMEM = "\nDelay";

/* Mode decided based on GPIO pin jumper placement:
 * PB2 - Update mode, fw_update can be run to load new protected firmware
 * PB3 - Readback mode, technician can run readback to read bytes from application memory space
 * Default - Boot firmware mode, firmware is verified (hash chain), if no issues bootloader transfers control
 */
int main(void)
{

    initialize_timer1();

    // Init UART1 (virtual com port)
    UART1_init();

    UART0_init();

    // Configure Port B Pins 2 and 3 as inputs.
    DDRB &= ~((1 << PB2) | (1 << PB3));

    // Enable pullups - give port time to settle.
    PORTB |= (1 << PB2) | (1 << PB3);

    // If jumper is present on pin 2, load new firmware.
    if(!(PINB & (1 << PB2)))
    {
        UART0_putchar('X');
        UART1_putchar('U');
        load_firmware();
    }
    else if(!(PINB & (1 << PB3)))
    {
        UART0_putchar('Z');
        UART1_putchar('R');
        readback();
    }
    else
    {
        UART1_putchar('B');
        boot_firmware();
    }
}

/*
 * Interface with host readback tool. Protocol steps:
 * 1. Main sends 'R' before calling readback, which activates watchdog. If no input, will reset.
 * 2. If host tool (readback) gets 'R', it will send 'S'
 * 3. On receipt of ‘S’, Bootloader encrypts a random nonce in ECB mode, sends to host.
 * 4. Host tool decrypts nonce, sends back encrypted control packet:
 *      IV-control || ((nonce || IV-data || start_addr || size ) || HMAC-SHA1 || Padding)
 * 5. Bootloader decrypts contol packet, if IV verifies will send requested data page-by-page
 * 6. Each data page is encrypted, the IV used is a hash chain originating from IV-data
 */
void readback(void)
{
    uint_farptr_t aes_desc_ptr;
    uint_farptr_t aes_key_ptr;

    // Crypto buffers
    uint8_t aes_key[AES_KEY_SIZE_BYTES];
    uint8_t aes_IVF[AES_IV_SIZE_BYTES];
    uint8_t hmac_sha1_computed[SHA1_HASH_SIZE_BYTES];
    uint8_t hmac_sha1_received[SHA1_HASH_SIZE_BYTES];
    uint8_t hmac_sha1_computed_invert[SHA1_HASH_SIZE_BYTES];
    uint8_t hmac_sha1_received_invert[SHA1_HASH_SIZE_BYTES];
    uint8_t sha1_temp[SHA1_HASH_SIZE_BYTES];
    aes256_ctx_t   ecb_ctx;
    bcal_cbc_ctx_t cbc_ctx;

    // Data buffers
    uint8_t nonce[AES_BLOCK_SIZE_BYTES];
    uint8_t nonce_received[AES_BLOCK_SIZE_BYTES];
    uint8_t nonce_computed_invert[AES_BLOCK_SIZE_BYTES];
    uint8_t nonce_received_invert[AES_BLOCK_SIZE_BYTES];
    uint8_t enc_nonce[AES_BLOCK_SIZE_BYTES];
    uint8_t response_buffer[RESPONSE_SIZE_BYTES];
    uint8_t tx_buffer[TX_TOTAL_SIZE_BYTES];
    
    uint16_t cbc_tx_data_to_hash_bits;
    int data_index = 0;
    uint16_t padding_len_bytes = 0;
    uint16_t cbc_data_to_hash_bits = 0;
    unsigned char signal;
    uint32_t req_start_addr;
    uint32_t actual_start_addr, actual_stop_addr;
    uint32_t max_end_addr = 0;                          // Safe default before re-assignment
    uint32_t req_size;

    // Start the Watchdog Timer
    wdt_enable(WDTO_4S);
    wdt_reset();

    // Wait for 'S'
    while(!UART1_data_available())
    {
        __asm__ __volatile__("");
    }
    if ('S' != (signal = UART1_getchar()))
    {
        while(1) __asm__ __volatile__(""); // Wait for watchdog timer to reset.
    }

    // Generate random value for nonce
    generate_nonce(nonce);
    wdt_reset();
    
    // Load AES key into local buffer
    aes_key_ptr = pgm_get_far_address(secret_key);
    memcpy_PF(aes_key, aes_key_ptr, AES_KEY_SIZE_BYTES);
    wdt_reset();
   
    // Initialize AES ECB-mode context with secret key
    memset(&ecb_ctx, 0, sizeof(aes256_ctx_t));
    aes256_init(aes_key, &ecb_ctx);
    wdt_reset();
    
    // Encrypt nonce with secret key in ecb mode
    memcpy(enc_nonce, nonce, AES_BLOCK_SIZE_BYTES);
    aes256_enc(enc_nonce, &ecb_ctx);
    wdt_reset();
    memset(&ecb_ctx, 0, sizeof(ecb_ctx));
    wdt_reset();

    // Send Enc(nonce) challenge
    for (int i = 0; i < AES_BLOCK_SIZE_BYTES; i++)
    {
        UART1_putchar(enc_nonce[i]);
        wdt_reset();
    }
    
    // Wait for response to nonce challenge and command
    while(!UART1_data_available())
    {
         __asm__ __volatile__("");
    }

    // Get the number of bytes specified
    for(int i = 0; i < RESPONSE_SIZE_BYTES; i++)
    {
        wdt_reset();
        response_buffer[data_index] = UART1_getchar();
        data_index++;
    }

    wdt_reset();
    
    // Initialize AES CBC-mode context with secret key
    memset(&cbc_ctx, 0, sizeof(cbc_ctx));
    aes_desc_ptr = pgm_get_far_address(aes256_desc);
    bcal_cbc_init(aes_desc_ptr, aes_key, AES_KEY_SIZE_BITS, &cbc_ctx); 
    wdt_reset();

    // Decrypt response
    // IVR is first AES_IV_SIZE_BYTES of response_buffer
    bcal_cbc_decMsg(response_buffer, (response_buffer + AES_IV_SIZE_BYTES), ((data_index/AES_BLOCK_SIZE_BYTES) -1), &cbc_ctx);

    wdt_reset();

    // Determine length of data to hash 
    padding_len_bytes = response_buffer[data_index-1]; // Assume last byte is padding
    cbc_data_to_hash_bits = ((data_index - AES_IV_SIZE_BYTES - SHA1_HASH_SIZE_BYTES - padding_len_bytes) << 3);

    // Compute signature and inverts for later verifcation
    hmac_sha1(hmac_sha1_computed, aes_key, AES_KEY_SIZE_BITS, (response_buffer + AES_IV_SIZE_BYTES), cbc_data_to_hash_bits);
    wdt_reset();
    memcpy(hmac_sha1_received, (response_buffer + data_index - padding_len_bytes - SHA1_HASH_SIZE_BYTES), SHA1_HASH_SIZE_BYTES);

    for (int i = 0; i < SHA1_HASH_SIZE_BYTES; i++) {
        hmac_sha1_computed_invert[i] = ~(hmac_sha1_computed[i]);
        hmac_sha1_received_invert[i] = ~(hmac_sha1_received[i]);
    }

    // Verify signature - 3 step for glitch attack resistance
    
    wdt_reset();
    delay = (my_rand() % DELAY_MAX);
    for (int i = 0; i < delay; i++) {
        overflow_counter++;
        __asm__ __volatile__("");
    }

    // 1. Memcmp output vs decrypted data block
    if ((memcmp(hmac_sha1_computed, (response_buffer + data_index - padding_len_bytes - SHA1_HASH_SIZE_BYTES), SHA1_HASH_SIZE_BYTES)) == 0) {

        wdt_reset();
        delay = (my_rand() % DELAY_MAX);
        for (int i = 0; i < delay; i++) {
            overflow_counter++;
            __asm__ __volatile__("");
        }

        // 2. Memcmp output inverted vs local buffer inverted
        if((memcmp(hmac_sha1_computed_invert, hmac_sha1_received_invert, SHA1_HASH_SIZE_BYTES)) == 0) {

            wdt_reset();
            delay = (my_rand() % DELAY_MAX);
            for (int i = 0; i < delay; i++) {
                overflow_counter++;
                __asm__ __volatile__("");
            }

            // 3. Memcmp output vs local buffer
            if((memcmp(hmac_sha1_computed, hmac_sha1_received, SHA1_HASH_SIZE_BYTES)) == 0) {

                __asm__ __volatile__("");

            } else {

                // Wipe cbc_ctx and key from SRAM
                memset(aes_key, 0, AES_KEY_SIZE_BYTES);
                wdt_reset();
                memset(&cbc_ctx, 0, sizeof(cbc_ctx));

                // Wait for watchdog timer to reset.
                while(1){
                    __asm__ __volatile__("");
                }

            } // 3.

        } else {

            // Wipe cbc_ctx and key from SRAM
            memset(aes_key, 0, AES_KEY_SIZE_BYTES);
            wdt_reset();
            memset(&cbc_ctx, 0, sizeof(cbc_ctx));

            // Wait for watchdog timer to reset.
            while(1){
                __asm__ __volatile__("");
            }

        } // 2.

    } else {

        // Wipe cbc_ctx and key from SRAM
        memset(aes_key, 0, AES_KEY_SIZE_BYTES);
        wdt_reset();
        memset(&cbc_ctx, 0, sizeof(cbc_ctx));

        // Wait for watchdog timer to reset.
        while(1){
            __asm__ __volatile__("");
        }

    } // 1.

    wdt_reset();
  
    // Extract received nonce and compute inverts for later verification
    memcpy(nonce_received, (response_buffer + AES_IV_SIZE_BYTES + RESPONSE_OFFSET_NONCE), AES_BLOCK_SIZE_BYTES);
    for (int i = 0; i < AES_BLOCK_SIZE_BYTES; i++) {
        nonce_computed_invert[i] = ~(nonce[i]);
        nonce_received_invert[i] = ~(nonce_received[i]);
    }
  
    // Verify nonce - 3 step for glitch attack resistance
   
    wdt_reset();
    delay = (my_rand() % DELAY_MAX);
    for (int i = 0; i < delay; i++) {
        overflow_counter++;
        __asm__ __volatile__("");
    }

    // 1. Memcmp output vs decrypted data block nonce
    if ((memcmp(nonce, (response_buffer + AES_IV_SIZE_BYTES + RESPONSE_OFFSET_NONCE), AES_BLOCK_SIZE_BYTES)) == 0) {

        wdt_reset();
        delay = (my_rand() % DELAY_MAX);
        for (int i = 0; i < delay; i++) {
            overflow_counter++;
            __asm__ __volatile__("");
        }

        // 2. Memcmp output inverted nonce vs local buffer inverted nonce
        if((memcmp(nonce_computed_invert, nonce_received_invert, AES_BLOCK_SIZE_BYTES)) == 0) {

            wdt_reset();
            delay = (my_rand() % DELAY_MAX);
            for (int i = 0; i < delay; i++) {
                overflow_counter++;
                __asm__ __volatile__("");
            }

            // 3. Memcmp output nonce vs local buffer nonce
            if((memcmp(nonce, nonce_received, AES_BLOCK_SIZE_BYTES)) == 0) {

                __asm__ __volatile__("");

            } else {

                // Wipe cbc_ctx and key from SRAM
                memset(aes_key, 0, AES_KEY_SIZE_BYTES);
                wdt_reset();
                memset(&cbc_ctx, 0, sizeof(cbc_ctx));

                // Wait for watchdog timer to reset.
                while(1){
                    __asm__ __volatile__("");
                }

            } // 3.

        } else {

            // Wipe cbc_ctx and key from SRAM
            memset(aes_key, 0, AES_KEY_SIZE_BYTES);
            wdt_reset();
            memset(&cbc_ctx, 0, sizeof(cbc_ctx));

            // Wait for watchdog timer to reset.
            while(1){
                __asm__ __volatile__("");
            }

        } // 2.

    } else {

        // Wipe cbc_ctx and key from SRAM
        memset(aes_key, 0, AES_KEY_SIZE_BYTES);
        wdt_reset();
        memset(&cbc_ctx, 0, sizeof(cbc_ctx));

        // Wait for watchdog timer to reset.
        while(1){
            __asm__ __volatile__("");
        }

    } // 1.

    // Authenticated message. Get IVF from response
    memcpy(aes_IVF, (response_buffer + AES_IV_SIZE_BYTES + RESPONSE_OFFSET_IVF), AES_IV_SIZE_BYTES);

    // Get req_start_addr for read
    req_start_addr  = ((uint32_t)response_buffer[AES_IV_SIZE_BYTES + RESPONSE_OFFSET_START_ADDR])     << 24;
    req_start_addr |= ((uint32_t)response_buffer[AES_IV_SIZE_BYTES + RESPONSE_OFFSET_START_ADDR + 1]) << 16;
    req_start_addr |= ((uint32_t)response_buffer[AES_IV_SIZE_BYTES + RESPONSE_OFFSET_START_ADDR + 2]) << 8;
    req_start_addr |= ((uint32_t)response_buffer[AES_IV_SIZE_BYTES + RESPONSE_OFFSET_START_ADDR + 3]);

    wdt_reset();

    // Get req_size of read (4 bytes)
    req_size  = ((uint32_t)response_buffer[AES_IV_SIZE_BYTES + RESPONSE_OFFSET_SIZE])     << 24;
    req_size |= ((uint32_t)response_buffer[AES_IV_SIZE_BYTES + RESPONSE_OFFSET_SIZE + 1]) << 16;
    req_size |= ((uint32_t)response_buffer[AES_IV_SIZE_BYTES + RESPONSE_OFFSET_SIZE + 2]) << 8;
    req_size |= ((uint32_t)response_buffer[AES_IV_SIZE_BYTES + RESPONSE_OFFSET_SIZE + 3]);

    wdt_reset();

    wdt_reset();
    delay = (my_rand() % DELAY_MAX);
    for (int i = 0; i < delay; i++) {
        overflow_counter++;
        __asm__ __volatile__("");
    }

    // Compute a max end address, accounting for possible macro trunkation
    max_end_addr = ((uint32_t)APP_START_ADDR + (uint32_t)MAX_ALLOWABLE_FIRMWARE_SIZE);

    req_size = (req_size < MAX_ALLOWABLE_FIRMWARE_SIZE) ? req_size : MAX_ALLOWABLE_FIRMWARE_SIZE; 
    actual_start_addr = ((req_start_addr + APP_START_ADDR) & PAGE_ALIGN_MASK);
    actual_stop_addr  = ((req_start_addr + APP_START_ADDR + req_size) & PAGE_ALIGN_MASK);

    wdt_reset();
    delay = (my_rand() % DELAY_MAX);
    for (int i = 0; i < delay; i++) {
        overflow_counter++;
        __asm__ __volatile__("");
    }

    // Set stop addr attempt #1
    actual_stop_addr  = (actual_stop_addr < max_end_addr) ? actual_stop_addr : (max_end_addr - SPM_PAGESIZE);
    
    wdt_reset();
    delay = (my_rand() % DELAY_MAX);
    for (int i = 0; i < delay; i++) {
        overflow_counter++;
        __asm__ __volatile__("");
    }

    // Set stop addr attempt #2
    actual_stop_addr  = (actual_stop_addr < max_end_addr) ? actual_stop_addr : (max_end_addr - SPM_PAGESIZE);

    wdt_reset();
    delay = (my_rand() % DELAY_MAX);
    for (int i = 0; i < delay; i++) {
        overflow_counter++;
        __asm__ __volatile__("");
    }

    // Set stop addr attempt #3
    actual_stop_addr  = (actual_stop_addr < max_end_addr) ? actual_stop_addr : (max_end_addr - SPM_PAGESIZE);
    
    wdt_reset();
    delay = (my_rand() % DELAY_MAX);
    for (int i = 0; i < delay; i++) {
        overflow_counter++;
        __asm__ __volatile__("");
    }

    // Initialize encryption context
    memset(&cbc_ctx, 0, sizeof(cbc_ctx));
    bcal_cbc_init(aes_desc_ptr, aes_key, AES_KEY_SIZE_BITS, &cbc_ctx); 
        
    for (uint32_t addr = actual_start_addr; addr <= actual_stop_addr; addr += TX_PAYLOAD_SIZE_BYTES)
    {
        uint32_t adjusted_addr;

        for (uint32_t tx_w_index = TX_OFFSET_PAYLOAD; 
             ((tx_w_index < (TX_OFFSET_PAYLOAD + TX_PAYLOAD_SIZE_BYTES)) && 
             (addr < max_end_addr));
            tx_w_index++)
        {
            // Read a byte from flash
            tx_buffer[tx_w_index] = pgm_read_byte_far(addr + tx_w_index - TX_OFFSET_PAYLOAD);
            wdt_reset();
        }

        // Copy address into TX_BUFFER
        adjusted_addr = addr - APP_START_ADDR;
        memcpy(&tx_buffer[TX_OFFSET_ADDRESS], &adjusted_addr, TX_ADDRESS_SIZE_BYTES);

        // Generate new IV -- First 16 bytes of sha1 hash -- chain rooted at initial aes_IVF
        sha1(sha1_temp, aes_IVF, AES_BLOCK_SIZE_BITS);
        memcpy(aes_IVF, sha1_temp, AES_BLOCK_SIZE_BYTES);
        wdt_reset();
    
        // Sign address and payload
        cbc_tx_data_to_hash_bits = ((TX_ADDRESS_SIZE_BYTES + TX_PAYLOAD_SIZE_BYTES) << 3);
        hmac_sha1((&tx_buffer[TX_OFFSET_SIGNATURE]), aes_key, AES_KEY_SIZE_BITS, tx_buffer, cbc_tx_data_to_hash_bits);
        wdt_reset();

        // Add padding
        for (uint16_t tx_w_index = TX_OFFSET_PADDING; tx_w_index < TX_TOTAL_SIZE_BYTES; tx_w_index++)
        {
            tx_buffer[tx_w_index] = (uint8_t) TX_PADDING_SIZE_BYTES;
        }

        // Encrypt payload
        wdt_reset();
        bcal_cbc_encMsg(aes_IVF, tx_buffer, (TX_TOTAL_SIZE_BYTES/16), &cbc_ctx);
        wdt_reset();

       // NOTE: we are not prepending the IV since host can regenerate the hash chain -- no reason to.

        UART1_flush();

        // Transmit
        for (uint16_t tx_r_index = 0; tx_r_index < TX_TOTAL_SIZE_BYTES; tx_r_index++)
        {
            UART1_putchar(tx_buffer[tx_r_index]);
            wdt_reset();
        }

        UART0_putstring("\nPg_sent");

        // Wait for OK
        while(!UART1_data_available())
        {
            __asm__ __volatile__("");
        }
        if ('T' != (signal = UART1_getchar()))
        {
            // Received something other than OK. Abort.
            // Wipe cbc_ctx and key from SRAM
            memset(aes_key, 0, AES_KEY_SIZE_BYTES);
            wdt_reset();
            memset(&cbc_ctx, 0, sizeof(cbc_ctx));
            while(1) __asm__ __volatile__(""); // Wait for watchdog timer to reset.
        }
        wdt_reset();
    }

    // Wipe cbc_ctx and key from SRAM
    memset(aes_key, 0, AES_KEY_SIZE_BYTES);
    wdt_reset();
    memset(&cbc_ctx, 0, sizeof(cbc_ctx));

    while(1) __asm__ __volatile__(""); // Wait for watchdog timer to reset.
}

/*
 * Load the firmware into flash.
 * 1. Bootloader decrypts each data page.
 * 2. Verifies HMAC signature.
 * 3. Verifies version number.
 * 4. Computes running has chain.
 * 5. Once last page recieved, waits for hash chain measurement from host tool.
 * 6. If measurement matches computed hash chain, update meta data, write to app start address, erase staging.
 *
 */
void load_firmware(void)
{
    uint16_t FIRMWARE_MAX_BYTES = MAX_ALLOWABLE_FIRMWARE_SIZE;
    uint16_t CBC_DATA_LEN = 304;

    uint_farptr_t aes_desc_ptr;
    uint_farptr_t aes_key_ptr;
    uint_farptr_t current_metadata_ptr;

    uint32_t rel_msg_write_addr;
    uint32_t app_page;

    int frame_length = 0;
    int rel_msg_index = 0;
    int new_rand_seed_index = 0;

    unsigned char rcv = 0;
    unsigned char data[CBC_DATA_LEN];
    unsigned char erase_page[SPM_PAGESIZE];

    unsigned int data_index = 0;
    unsigned int page = APP_START_ADDR;

    uint16_t version = 1; // Safe default
    uint16_t size = 0;
    uint16_t firmware_bytes = 0;
    uint16_t cbc_data_to_hash_bits = 0;
    uint16_t cbc_data_frame_count = 0;
    uint16_t padding_len_bytes = 0;
    uint16_t current_fw_version = 0xFFFF; // Update will be pulled from metadata stuct, this value is a failsafe
    uint16_t last_page_data_len; 
    uint16_t debug_flag = 0; // important to do this so that other versions are not in debug mode 

    // String buffers
    char rel_msg[1025];

    // Crypto buffers
    uint8_t aes_key[AES_KEY_SIZE_BYTES];
    uint8_t hmac_sha1_computed[SHA1_HASH_SIZE_BYTES];
    uint8_t hmac_sha1_received[SHA1_HASH_SIZE_BYTES];
    uint8_t hmac_sha1_computed_invert[SHA1_HASH_SIZE_BYTES];
    uint8_t hmac_sha1_received_invert[SHA1_HASH_SIZE_BYTES];
    uint8_t new_rand_seed[RANDOM_SEED_SIZE_BYTES];
    uint8_t running_hash_pair[2*SHA1_HASH_SIZE_BYTES];
    uint8_t firmware_final_hash_computed[SHA1_HASH_SIZE_BYTES];
    uint8_t firmware_final_hash_received[SHA1_HASH_SIZE_BYTES];
    
    // Start the Watchdog Timer
    wdt_enable(WDTO_4S);
    wdt_reset();

    // Initialize erase page
    for (uint16_t i = 0; i < SPM_PAGESIZE; i++) {
        erase_page[i] = 0xFF;
    }

    wdt_reset();

    // Load AES key into local buffer, want to pass it in SRAM
    aes_key_ptr = pgm_get_far_address(secret_key);
    memcpy_PF(aes_key, aes_key_ptr, AES_KEY_SIZE_BYTES);
    wdt_reset();

    // Initialize a metadata pointer for later use, get version information
    current_metadata_ptr = pgm_get_far_address(fw_metadata);
    current_fw_version = pgm_read_word_far(current_metadata_ptr + offsetof(union fw_metadata, fw_version));

    // AES CBC Context init
    bcal_cbc_ctx_t ctx;
    memset(&ctx, 0, sizeof(bcal_cbc_ctx_t));
    wdt_reset();

    aes_desc_ptr = pgm_get_far_address(aes256_desc);
    wdt_reset();

    bcal_cbc_init(aes_desc_ptr, aes_key, AES_KEY_SIZE_BITS, &ctx);
    wdt_reset();

    /* Wait for data */
    while(!UART1_data_available())
    {
        __asm__ __volatile__("");
    }

    // Get size
    rcv = UART1_getchar();
    size = (uint16_t)rcv << 8;
    rcv = UART1_getchar();
    size |= (uint16_t)rcv;

    // Acknowledge the metadata, ready for frame send
    UART1_putchar(OK);
    wdt_reset();
 
    /* Loop here until you can get all your characters and stuff */
    while (firmware_bytes < FIRMWARE_MAX_BYTES)
    {
        wdt_reset();

        // Get two bytes for the length.
        rcv = UART1_getchar();
        frame_length = (int)rcv << 8;
        rcv = UART1_getchar();
        frame_length += (int)rcv;

        wdt_reset();

        // Get the number of bytes specified
        for(int i = 0; i < frame_length; ++i){
            wdt_reset();
            data[data_index] = UART1_getchar();
            data_index += 1;

        }

        // If we fill page buffer: decrypt, verify, program
        if(data_index == CBC_DATA_LEN || frame_length == 0)
        {

            cbc_data_frame_count += 1;

            // Decrypt block of data
            wdt_reset();
            bcal_cbc_decMsg(data, (data + AES_IV_SIZE_BYTES), ((data_index/AES_BLOCK_SIZE_BYTES) - 1), &ctx);
            wdt_reset();

            // Determine length of data to hash
            padding_len_bytes = data[data_index-1];
            cbc_data_to_hash_bits = ((data_index - AES_IV_SIZE_BYTES - SHA1_HASH_SIZE_BYTES - padding_len_bytes) << 3);
           
            // ******************************************************************
            // SIGNATURE CHECK
            // ******************************************************************

            // Compute signature and inverts for later verifcation
            
            wdt_reset();
            hmac_sha1(hmac_sha1_computed, aes_key, AES_KEY_SIZE_BITS, (data + AES_IV_SIZE_BYTES), cbc_data_to_hash_bits);
            wdt_reset();
            memcpy(hmac_sha1_received, (data + data_index - padding_len_bytes - SHA1_HASH_SIZE_BYTES), SHA1_HASH_SIZE_BYTES);
            wdt_reset();

            for (int i = 0; i < SHA1_HASH_SIZE_BYTES; i++) {
                hmac_sha1_computed_invert[i] = ~(hmac_sha1_computed[i]);
                hmac_sha1_received_invert[i] = ~(hmac_sha1_received[i]);
            }

            wdt_reset();

            // Verify signature - 3 step for glitch attack resistance
            
            wdt_reset();
            delay = (my_rand() % DELAY_MAX);
            for (int i = 0; i < delay; i++) {
                overflow_counter++;
                __asm__ __volatile__("");
            }

            // 1. Memcmp output vs decrypted data block
            if ((memcmp(hmac_sha1_computed, (data + data_index - padding_len_bytes - SHA1_HASH_SIZE_BYTES), SHA1_HASH_SIZE_BYTES)) == 0) {
 
                wdt_reset();
                delay = (my_rand() % DELAY_MAX);
                for (int i = 0; i < delay; i++) {
                    overflow_counter++;
                    __asm__ __volatile__("");
                }

                // 2. Memcmp output inverted vs local buffer inverted
                if((memcmp(hmac_sha1_computed_invert, hmac_sha1_received_invert, SHA1_HASH_SIZE_BYTES)) == 0) {

                    wdt_reset();
                    delay = (my_rand() % DELAY_MAX);
                    for (int i = 0; i < delay; i++) {
                        overflow_counter++;
                        __asm__ __volatile__("");
                    }

                    // 3. Memcmp output vs local buffer
                    if((memcmp(hmac_sha1_computed, hmac_sha1_received, SHA1_HASH_SIZE_BYTES)) == 0) {

                        __asm__ __volatile__("");
                        wdt_reset();

                    } else {

                        // Wipe cbc_ctx and key from SRAM
                        memset(aes_key, 0, AES_KEY_SIZE_BYTES);
                        wdt_reset();
                        memset(&ctx, 0, sizeof(ctx));

                        wdt_reset();
                        
                        if (cbc_data_frame_count > 1) {

                            // Malicious firmware - nuke it!
                            for (app_page = APP_START_ADDR; app_page < (APP_START_ADDR + FIRMWARE_MAX_BYTES); app_page += SPM_PAGESIZE) {
                                
                                // Erase page
                                wdt_reset();
                                program_flash(app_page, erase_page);
                                wdt_reset();

                            }

                        }
                        
                        // Wait for watchdog timer to reset.
                        while(1){
                            __asm__ __volatile__("");
                        }

                    } // 3.

                } else {
                    
                    // Wipe cbc_ctx and key from SRAM
                    memset(aes_key, 0, AES_KEY_SIZE_BYTES);
                    wdt_reset();
                    memset(&ctx, 0, sizeof(ctx));

                    wdt_reset();

                    if (cbc_data_frame_count > 1) {

                        // Malicious firmware - nuke it!
                        for (app_page = APP_START_ADDR; app_page < (APP_START_ADDR + FIRMWARE_MAX_BYTES); app_page += SPM_PAGESIZE) {
                            
                            // Erase page
                            wdt_reset();
                            program_flash(app_page, erase_page);
                            wdt_reset();

                        }

                    }

                    // Wait for watchdog timer to reset.
                    while(1){
                        __asm__ __volatile__("");
                    }

                } // 2.

            } else {

                // Wipe cbc_ctx and key from SRAM
                memset(aes_key, 0, AES_KEY_SIZE_BYTES);
                wdt_reset();
                memset(&ctx, 0, sizeof(ctx));

                wdt_reset();

                if (cbc_data_frame_count > 1) {

                    // Malicious firmware - nuke it!
                    for (app_page = APP_START_ADDR; app_page < (APP_START_ADDR + FIRMWARE_MAX_BYTES); app_page += SPM_PAGESIZE) {
                        
                        // Erase page
                        wdt_reset();
                        program_flash(app_page, erase_page);
                        wdt_reset();

                    }

                }

                // Wait for watchdog timer to reset.
                while(1){
                    __asm__ __volatile__("");
                }

            } // 1.

            // ******************************************************************
            // VERSION CHECK
            // ******************************************************************
        
            // Extract version number
            rcv = data[AES_IV_SIZE_BYTES];
            version = (int)rcv << 8;
            rcv = data[AES_IV_SIZE_BYTES + 1];
            version += (int)rcv;

            wdt_reset();
            delay = (my_rand() % DELAY_MAX);
            for (int i = 0; i < delay; i++) {
                overflow_counter++;
                __asm__ __volatile__("");
            }

            // Compare to old version and abort if older (note special case for version 0).
            if ((version == 0) || (version >= current_fw_version)) {

                wdt_reset();
                delay = (my_rand() % DELAY_MAX);
                for (int i = 0; i < delay; i++) {
                    overflow_counter++;
                    __asm__ __volatile__("");
                }

                if ((current_fw_version <= version) || (version == 0)) {

                    wdt_reset();
                    delay = (my_rand() % DELAY_MAX);
                    for (int i = 0; i < delay; i++) {
                        overflow_counter++;
                        __asm__ __volatile__("");
                    }

                    // Overwrite zero to keep previous
                    if (version == 0) {
                        version = current_fw_version;
                        debug_flag = 1;
                    }
                    wdt_reset();

                } else {

                    // Wipe cbc_ctx and key from SRAM
                    memset(aes_key, 0, AES_KEY_SIZE_BYTES);
                    wdt_reset();
                    memset(&ctx, 0, sizeof(ctx));

                     // Wait for watchdog timer to reset.
                    while(1) {
                        __asm__ __volatile__("");
                    }

                }

            } else {

                 // Wipe cbc_ctx and key from SRAM
                memset(aes_key, 0, AES_KEY_SIZE_BYTES);
                wdt_reset();
                memset(&ctx, 0, sizeof(ctx));
               
                // Wait for watchdog timer to reset.
                while(1) {
                    __asm__ __volatile__("");
                }

            }

            // ******************************************************************
            // HASH CHAIN COMPUTATION
            // ******************************************************************
            
            // First page - seed hash chain
            if (cbc_data_frame_count == 1) {

                wdt_reset();

                // Seed first half of running hash pair
                memcpy(running_hash_pair, hmac_sha1_computed, SHA1_HASH_SIZE_BYTES);

            // All subsequent pages - iterate hash chain
            } else {

                // Update latter half of running hash pair
                wdt_reset();
                memcpy((running_hash_pair + SHA1_HASH_SIZE_BYTES), hmac_sha1_computed, SHA1_HASH_SIZE_BYTES);

                // Compute next round's input
                wdt_reset();
                sha1(firmware_final_hash_computed, running_hash_pair, (2 * SHA1_HASH_SIZE_BYTES * 8));
                wdt_reset();

                // Seed first half of running hash pair for next round
                memcpy(running_hash_pair, firmware_final_hash_computed, SHA1_HASH_SIZE_BYTES);
                wdt_reset();
            }

            // ******************************************************************
            // PAYLOAD PARSING
            // ******************************************************************

            // Parse individual data frames
            if ((cbc_data_frame_count > 0) && (cbc_data_frame_count < 5)) {

                wdt_reset();

               // Collect majority of release message
                for(int i = AES_IV_SIZE_BYTES + VERSION_OFFSET; i < AES_IV_SIZE_BYTES + VERSION_OFFSET + SPM_PAGESIZE; ++i) {
                    rel_msg[rel_msg_index] = data[i];
                    rel_msg_index++;
                }

                wdt_reset();

            } else if (cbc_data_frame_count == 5) {

                wdt_reset();

                // Null terminate
                rel_msg[rel_msg_index] = '\0';

                wdt_reset();

                // Collect new random seed
                for(int i = (AES_IV_SIZE_BYTES + VERSION_OFFSET); i < (AES_IV_SIZE_BYTES + VERSION_OFFSET + RANDOM_SEED_SIZE_BYTES); ++i) {
                    new_rand_seed[new_rand_seed_index] = data[i];
                    new_rand_seed_index++;
                }

                wdt_reset();

            } else {

                wdt_reset();

                // Update data counter
                if ((frame_length == 0) || (firmware_bytes < SPM_PAGESIZE)) {

                    last_page_data_len = (data_index - AES_IV_SIZE_BYTES -VERSION_OFFSET - SHA1_HASH_SIZE_BYTES - padding_len_bytes);
                    firmware_bytes += last_page_data_len;

                    wdt_reset();
                    for (int i = (last_page_data_len + AES_IV_SIZE_BYTES + VERSION_OFFSET); i < SPM_PAGESIZE + AES_IV_SIZE_BYTES + VERSION_OFFSET; i++) {
                        data[i] = 0xFF;
                    }
                    wdt_reset();

                } else {

                    wdt_reset();
                    firmware_bytes += SPM_PAGESIZE;

                }

                // Program page
                wdt_reset();
                program_flash(page, (data + AES_IV_SIZE_BYTES + VERSION_OFFSET));
                page += SPM_PAGESIZE;
                wdt_reset();

                // Final page written
                if(frame_length == 0) {
                    break;
                }

            }

            wdt_reset();

            // Minimal print
            UART0_putchar('P');

            // Reset data index
            data_index = 0;

            wdt_reset();

        } // if

        UART1_putchar(OK); // Acknowledge the frame.
    }

    // ******************************************************************
    // FINAL FRAME VERIFICATION
    // ******************************************************************
    
    wdt_reset();
    
    data_index = 0;

    // Collect last frame's data
    while (data_index < FINAL_FRAME_SIZE_BYTES) {

        wdt_reset();

        // Get two bytes for the length.
        rcv = UART1_getchar();
        frame_length = (int)rcv << 8;
        rcv = UART1_getchar();
        frame_length += (int)rcv;

        wdt_reset();
        
        // Get the number of bytes specified
        for(int i = 0; i < frame_length; ++i){
            wdt_reset();
            data[data_index] = UART1_getchar();
            data_index += 1;
        }

        wdt_reset();
        
        UART1_putchar(OK); // Acknowledge the frame.
        UART0_putchar('M'); // Acknowledge the frame.
    }
    
    // Decrypt block of data
    wdt_reset();
    bcal_cbc_decMsg(data, (data + AES_IV_SIZE_BYTES), ((data_index/AES_BLOCK_SIZE_BYTES) - 1), &ctx);
    wdt_reset();

    // Determine length of data to hash
    wdt_reset();
    padding_len_bytes = data[data_index-1];
    cbc_data_to_hash_bits = ((data_index - AES_IV_SIZE_BYTES - SHA1_HASH_SIZE_BYTES - padding_len_bytes) << 3);
    wdt_reset();

    // Compute signature and inverts for later verifcation
    wdt_reset();
    hmac_sha1(hmac_sha1_computed, aes_key, AES_KEY_SIZE_BITS, (data + AES_IV_SIZE_BYTES), cbc_data_to_hash_bits);
   
    wdt_reset();
    delay = (my_rand() % DELAY_MAX);
    for (int i = 0; i < delay; i++) {
        overflow_counter++;
        __asm__ __volatile__("");
    }

    // Verify final frame signature
    if ((memcmp(hmac_sha1_computed, (data + data_index - padding_len_bytes - SHA1_HASH_SIZE_BYTES), SHA1_HASH_SIZE_BYTES)) == 0) {

        wdt_reset();
        delay = (my_rand() % DELAY_MAX);
        for (int i = 0; i < delay; i++) {
            overflow_counter++;
            __asm__ __volatile__("");
        }

        if ((memcmp((data + data_index - padding_len_bytes - SHA1_HASH_SIZE_BYTES), hmac_sha1_computed, SHA1_HASH_SIZE_BYTES)) == 0) {

            // Extract measurement signature
            wdt_reset();
            memcpy(firmware_final_hash_received, (data + AES_IV_SIZE_BYTES + VERSION_OFFSET), SHA1_HASH_SIZE_BYTES);
        
        } else {

            // Wipe cbc_ctx and key from SRAM
            memset(aes_key, 0, AES_KEY_SIZE_BYTES);
            wdt_reset();
            memset(&ctx, 0, sizeof(ctx));

            // Wait for watchdog timer to reset.
            while(1){
                __asm__ __volatile__("");
            }

        }

    } else {

        // Wipe cbc_ctx and key from SRAM
        memset(aes_key, 0, AES_KEY_SIZE_BYTES);
        wdt_reset();
        memset(&ctx, 0, sizeof(ctx));

        // Wait for watchdog timer to reset.
        while(1){
            __asm__ __volatile__("");
        }

    }

    wdt_reset();

    // Initialize erase page
    for (uint16_t i = 0; i < SPM_PAGESIZE; i++) {
        erase_page[i] = 0xFF;
    }

    wdt_reset();
    delay = (my_rand() % DELAY_MAX);
    for (int i = 0; i < delay; i++) {
        overflow_counter++;
        __asm__ __volatile__("");
    }

    // Verify final hash
    if ((memcmp(firmware_final_hash_computed, firmware_final_hash_received, SHA1_HASH_SIZE_BYTES)) == 0) {
    
        wdt_reset();
        delay = (my_rand() % DELAY_MAX);
        for (int i = 0; i < delay; i++) {
            overflow_counter++;
            __asm__ __volatile__("");
        }

        if ((memcmp(firmware_final_hash_received, firmware_final_hash_computed, SHA1_HASH_SIZE_BYTES)) == 0) {

            // ******************************************************************
            // METADATA UPDATE
            // ******************************************************************

            wdt_reset();

            // Update firmware metadata for version checks and boot-time verification
            write_fw_metadata_to_vault(firmware_bytes, version, firmware_final_hash_computed, new_rand_seed, debug_flag);

            // Write release message (4 pages)
            rel_msg_write_addr = RELEASE_MSG_ADDR;
            for (int i = 0; i < RELEASE_MSG_MAX_SIZE; i += SPM_PAGESIZE, rel_msg_write_addr += SPM_PAGESIZE) {

                wdt_reset();
                program_flash(rel_msg_write_addr, &rel_msg[i]);

            }

            UART0_putstring("\nFW metadata updated.");

        } else {
            
            // Wipe cbc_ctx and key from SRAM
            memset(aes_key, 0, AES_KEY_SIZE_BYTES);
            wdt_reset();
            memset(&ctx, 0, sizeof(ctx));

            wdt_reset();

            // Malicious firmware - nuke it!
            for (app_page = APP_START_ADDR; app_page < (APP_START_ADDR + FIRMWARE_MAX_BYTES); app_page += SPM_PAGESIZE) {
                
                // Erase page
                wdt_reset();
                program_flash(app_page, erase_page);
                wdt_reset();

            }

            // Wait for watchdog timer to reset.
            while(1){
                __asm__ __volatile__("");
            }

        }

    } else {

        // Wipe cbc_ctx and key from SRAM
        memset(aes_key, 0, AES_KEY_SIZE_BYTES);
        wdt_reset();
        memset(&ctx, 0, sizeof(ctx));

        wdt_reset();

        // Malicious firmware - nuke it!
        for (app_page = APP_START_ADDR; app_page < (APP_START_ADDR + FIRMWARE_MAX_BYTES); app_page += SPM_PAGESIZE) {
            
            // Erase page
            wdt_reset();
            program_flash(app_page, erase_page);
            wdt_reset();

        }

        // Wait for watchdog timer to reset.
        while(1){
            __asm__ __volatile__("");
        }

    }

    wdt_reset();

    // Erase the key from SRAM, no longer needed
    memset(aes_key, 0, AES_KEY_SIZE_BYTES);
    wdt_reset();
    memset(&ctx, 0, sizeof(ctx));
    wdt_reset();
    
    // Wait for watchdog timer to reset.
    while(1)
    {
	__asm__ __volatile__("");
    }

}

/*
 * Ensure the firmware is loaded correctly and boot it up.
 * 1. Read firmware size and hash chain measurement from secret storage.
 * 2. Reconstructs/recomputes hash chain. If matches what is in app memory, transfers control to app.
 */
void boot_firmware(void)
{
    uint_farptr_t current_metadata_ptr;
    uint_farptr_t aes_key_ptr;
    uint_farptr_t current_signature_ptr;
    uint_farptr_t current_random_ptr;

    uint16_t current_fw_size, current_fw_version;
    uint8_t cur_byte;
    uint16_t page_size;

    // HMAC two blocks, concatenate those HMACs and SHA1 them to get the hash chain.
    unsigned char data[SPM_PAGESIZE + VERSION_OFFSET]; // This is the data we hash, Hash includes code and version number
    unsigned char hmacs[2*SHA1_HASH_SIZE_BYTES];  

    uint32_t release_msg_addr = RELEASE_MSG_ADDR; // Start address of release message
    uint32_t app_page;
    uint16_t FIRMWARE_MAX_BYTES = MAX_ALLOWABLE_FIRMWARE_SIZE;

    // Take care of the condition where size is less than one page size
    // Read the key
    uint32_t addr = APP_START_ADDR; // Used to loop over firmware
    uint32_t last_addr; // last address of firmware
    uint8_t hash[SHA1_HASH_SIZE_BYTES]; // Holds hash of hmacs of consecutive pages temporarily
    uint8_t cbc_data_frame_count = 0;
    uint8_t key[AES_KEY_SIZE_BYTES]; // AES key to verify signature
    uint8_t sha_chain[SHA1_HASH_SIZE_BYTES]; // value of hash chain from secret vault
    uint8_t sha_chain_inverted[SHA1_HASH_SIZE_BYTES]; // temporary stuff
    uint8_t computed_sha_chain_inverted[SHA1_HASH_SIZE_BYTES];
    uint8_t rand_seed[RANDOM_SEED_SIZE_BYTES];
    uint16_t current_debug_flag = 0;
    unsigned char erase_page[SPM_PAGESIZE];

    // Initialize a metadata pointer for later use, get size of firmware
    current_metadata_ptr = pgm_get_far_address(fw_metadata);
    current_fw_size = pgm_read_word_far(current_metadata_ptr + offsetof(union fw_metadata, fw_size));
    current_fw_version = pgm_read_word_far(current_metadata_ptr + offsetof(union fw_metadata, fw_version));
    current_debug_flag =pgm_read_word_far(current_metadata_ptr + offsetof(union fw_metadata, fw_debug));
    
    last_addr = (addr + current_fw_size - 1);

    // Read sha chain stored
    current_signature_ptr = (current_metadata_ptr + offsetof(union fw_metadata, fw_signature));
    memcpy_PF(sha_chain, current_signature_ptr, SHA1_HASH_SIZE_BYTES);

    // Read stored rand seed
    current_random_ptr = (current_metadata_ptr + offsetof(union fw_metadata, fw_random_seed));
    memcpy_PF(rand_seed, current_random_ptr, RANDOM_SEED_SIZE_BYTES);

    // Load AES key into local buffer, want to pass it in SRAM
    aes_key_ptr = pgm_get_far_address(secret_key);
    memcpy_PF(key, aes_key_ptr, AES_KEY_SIZE_BYTES);

    // Start the Watchdog Timer.
    wdt_enable(WDTO_4S);

    // Reset if firmware size is 0 (indicates no firmware is loaded).
    if (current_fw_size == 0) {

        UART0_putstring("\nNo FW!\n");
        // Wait for watchdog timer to reset.
        while(1) __asm__ __volatile__("");

    }

    wdt_reset();

    if (current_debug_flag == 1) {
        data[1] = 0;
        data[0] = 0;
    } else {
        data[1] = *((unsigned char *)&current_fw_version);
        data[0] = *(((unsigned char *)&current_fw_version) + 1);
    }

    wdt_reset();

    addr = APP_START_ADDR;
    release_msg_addr = RELEASE_MSG_ADDR;
    cbc_data_frame_count = 1;

    while(addr <= last_addr){

        wdt_reset();

        if (addr + SPM_PAGESIZE < last_addr) {
            page_size = SPM_PAGESIZE;
        } else {
            page_size = (last_addr - addr + 1);
        }
       
        wdt_reset();

        // Reconstuct release message frames
        if (cbc_data_frame_count < 5) {

            // Read a page-sized chunck of release message from memory
            for(uint16_t i = VERSION_OFFSET ; i < (SPM_PAGESIZE + VERSION_OFFSET); i++) {
                wdt_reset();
                data[i] = pgm_read_byte_far(release_msg_addr);
                release_msg_addr++;
            }

        // Reconstuct rand_seed_frame
        } else if (cbc_data_frame_count == 5) {

            // Read rand seed from initialized local buffer
            for(uint16_t i = VERSION_OFFSET; i < (RANDOM_SEED_SIZE_BYTES + VERSION_OFFSET); i++){
                wdt_reset();
                data[i] = rand_seed[i-VERSION_OFFSET];
            }

            // Pad remainder
            for(uint16_t i = (RANDOM_SEED_SIZE_BYTES + VERSION_OFFSET); i < (SPM_PAGESIZE + VERSION_OFFSET); i++){
                wdt_reset();
                data[i] = 0xFF;
            }

        // Read code from the applicaction section
        } else {

            // Read a page from memory
            for(uint16_t i = VERSION_OFFSET ; i < (page_size + VERSION_OFFSET); i++){ 
                wdt_reset();
                data[i] = pgm_read_byte_far(addr);
                addr++;
            }

        }

        wdt_reset();

        delay = (my_rand() % DELAY_MAX);
        for (int i = 0; i < delay; i++) {
            overflow_counter++;
            __asm__ __volatile__("");
        }
 
        if (cbc_data_frame_count == 1) { // Calculate hmac of first page

            wdt_reset();
            hmac_sha1(hmacs, key, AES_KEY_SIZE_BITS, data, ((page_size+VERSION_OFFSET) * 8));
            wdt_reset();

        } else { // Calculate hmac of second page and store it in second half of hmacs and then calculate sha1 of "hmacs" ie hash the hmacs of previous two pages then store it at first half of hmacs

            wdt_reset();
            hmac_sha1(hmacs + SHA1_HASH_SIZE_BYTES, key, AES_KEY_SIZE_BITS, data, ((page_size+VERSION_OFFSET) * 8));
            wdt_reset();
            sha1(hash, hmacs, (2*SHA1_HASH_SIZE_BYTES*8)); // Calculate hash of full "hmacs"
            memcpy(hmacs, hash, SHA1_HASH_SIZE_BYTES); // Copy hash to first part of hmacs
            wdt_reset();

        }

        cbc_data_frame_count++;

    }

    // Erase the key now that the key is not required (note no ctx struct, since hashing not encrypting)
    memset(key, 0, AES_KEY_SIZE_BYTES);
    wdt_reset();

    // Initialize erase page
    for (uint16_t i = 0; i < SPM_PAGESIZE; i++) {
        erase_page[i] = 0xFF;
    }

    wdt_reset();

    // Store an inverted copy of computed sha chain which is currently in first half of "hmacs"
    // Store an inverted copy of sha chain which is currently in sha_chain, this value is obtained from secret vault
    for (uint8_t i=0 ;i < SHA1_HASH_SIZE_BYTES; i++){
        computed_sha_chain_inverted[i] = ~hash[i];
        sha_chain_inverted[i] = ~sha_chain[i];
    }

    wdt_reset();
    delay = (my_rand() % DELAY_MAX);
    for (int i = 0; i < delay; i++) {
        overflow_counter++;
        __asm__ __volatile__("");
    }

    // Compare secret SHA1 chain value with the computed value in
    // Anti Glitch 3 inverted comparisons
    if(memcmp(hash, sha_chain, SHA1_HASH_SIZE_BYTES) == 0){

        wdt_reset();
        delay = (my_rand() % DELAY_MAX);
        for (int i = 0; i < delay; i++) {
            overflow_counter++;
            __asm__ __volatile__("");
        }

        if(memcmp(computed_sha_chain_inverted, sha_chain_inverted, SHA1_HASH_SIZE_BYTES ) == 0){

            wdt_reset();
            delay = (my_rand() % DELAY_MAX);
            for (int i = 0; i < delay; i++) {
                overflow_counter++;
                __asm__ __volatile__("");
            }

            if(memcmp(hash, sha_chain, SHA1_HASH_SIZE_BYTES) == 0){

                // Write out release message to UART0.
                wdt_reset();
                uint32_t i = 0;
                UART0_putchar('\n');
                release_msg_addr = RELEASE_MSG_ADDR; // RELEASE_MSG_ADDR contains start address of release message
                do {

                    wdt_reset();
                    cur_byte = pgm_read_byte_far(release_msg_addr);
                    UART0_putchar(cur_byte);
                    release_msg_addr++;
                    i++;

                } while ((cur_byte != 0) && (i < RELEASE_MSG_MAX_SIZE)); // Stop if you have reached max size
                wdt_reset();
                UART0_putchar('\n');
                
                // Clear stack before passing control to app
                current_metadata_ptr = 0;
                aes_key_ptr = 0;
                current_signature_ptr = 0;
                current_random_ptr = 0;
                current_fw_size = 0;
                current_fw_version = 0;
                cur_byte = 0;
                page_size = 0;
                memset(data, 0, sizeof(data));
                wdt_reset();
                memset(hmacs, 0, sizeof(hmacs));
                release_msg_addr = 0;
                addr = 0;
                last_addr = 0;
                wdt_reset();
                memset(hash, 0, sizeof(hash));
                cbc_data_frame_count = 0;
                memset(key, 0, sizeof(key));
                memset(sha_chain, 0, sizeof(sha_chain));
                wdt_reset();
                memset(sha_chain_inverted, 0, sizeof(sha_chain_inverted));
                memset(computed_sha_chain_inverted, 0, sizeof(computed_sha_chain_inverted));
                wdt_reset();
                memset(rand_seed, 0, sizeof(rand_seed));
                current_debug_flag = 0;

                // Stop the Watchdog Timer.
                wdt_disable();

                // Make the leap of faith.
                asm ("jmp 0x2f00");

            } else {

                wdt_reset();

                // Malicious firmware - nuke it!
                for (app_page = APP_START_ADDR; app_page < (APP_START_ADDR + FIRMWARE_MAX_BYTES); app_page += SPM_PAGESIZE) {
                    
                    // Erase page
                    wdt_reset();
                    program_flash(app_page, erase_page);
                    wdt_reset();

                }

                UART0_putstring("\nVerification failed!\n");

                // Wait for watchdog timer to reset.
                while(1) {
                __asm__ __volatile__("");
                }

            }

        } else {

            wdt_reset();

            // Malicious firmware - nuke it!
            for (app_page = APP_START_ADDR; app_page < (APP_START_ADDR + FIRMWARE_MAX_BYTES); app_page += SPM_PAGESIZE) {
                
                // Erase page
                wdt_reset();
                program_flash(app_page, erase_page);
                wdt_reset();

            }

            UART0_putstring("\nVerification failed!\n");

            // Wait for watchdog timer to reset.
            while(1) {
                __asm__ __volatile__("");
            }
        }

    } else {

        wdt_reset();

        // Malicious firmware - nuke it!
        for (app_page = APP_START_ADDR; app_page < (APP_START_ADDR + FIRMWARE_MAX_BYTES); app_page += SPM_PAGESIZE) {
            
            // Erase page
            wdt_reset();
            program_flash(app_page, erase_page);
            wdt_reset();

        }

        UART0_putstring("\nVerification failed!\n");

        // Wait for watchdog timer to reset.
        while(1) {
            __asm__ __volatile__("");
        }
    }

    // Hang if glitched
    while(1) {
        __asm__ __volatile__("");
    }

}

/*
 * To program flash, you need to access and program it in pages
 * On the atmega1284p, each page is 128 words, or 256 bytes
 *
 * Programing involves four things,
 * 1. Erasing the page
 * 2. Filling a page buffer
 * 3. Writing a page
 * 4. When you are done programming all of your pages, enable the flash
 *
 * You must fill the buffer one word at a time
 */
void program_flash(uint32_t page_address, unsigned char *data)
{
    int i = 0;

    boot_page_erase_safe(page_address);

    for(i = 0; i < SPM_PAGESIZE; i += 2)
    {
        uint16_t w = data[i];    // Make a word out of two bytes
        w += data[i+1] << 8;
        boot_page_fill_safe(page_address+i, w);
    }

    boot_page_write_safe(page_address);
    boot_rww_enable_safe(); // We can just enable it after every program too
}
