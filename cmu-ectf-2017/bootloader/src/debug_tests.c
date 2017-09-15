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

#include "debug_tests.h"

// Test string ptins
void UART1_putstring_P(const char *str)
{
    while(pgm_read_byte_far(str) != 0x0)
    {
        UART1_putchar(pgm_read_byte_far(str++));
    }
}

// For custom format printing test's debug messages over UART1
void print_debug_msg(char *header, uint8_t *data, uint8_t data_len)
{

        int i;

        // Print until null terminator is hit
        UART1_putstring(header);

        // Print data character by character
        for (i = 0; i < data_len; i++) {
            UART1_putchar(data[i]);
        }

        // Null terminate data
        UART1_putchar((unsigned char)0);

}

// Make sure plain AES is working, no IV or CBC
void test_aes256_basic(void)
{
        // 32 byte (256-bit) test key, for both AES_256 and HMAC_SHA1
        uint8_t test_key[AES_KEY_SIZE_BYTES] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};

        // aes256 is 16 byte data size
        uint8_t data[16] = "text to encrypt";

        UART1_putstring("\nAES_256 Key:\n");
        UART1_print_hex(test_key, AES_KEY_SIZE_BYTES);
 
        print_debug_msg("\nAES_256 plaintext:\n", data, 16);

        // declare the context where the round keys are stored
        aes256_ctx_t ctx;
        memset(&ctx, 0, sizeof(aes256_ctx_t));

        // Initialize the AES256 with the desired key
        aes256_init(test_key, &ctx);

        // Encrypt data
        // "text to encrypt" (ascii) -> '9798D10A63E4E167122C4C07AF49C3A9'(hexa)
        aes256_enc(data, &ctx);

        /*
        // Data to hex
        int i;
        uint8_t temp[16];
        for (i = 0; i < 16; i++)
        {
           temp[i] = hexa_to_ascii(data[i]);
        }
        */

        // New hex print
        UART1_putstring("\nAES_256 Cipertext:\n");
        UART1_print_hex(data, 16);

        //print_debug_msg("\nAES_256 Cipertext:\n", temp, 16);

        // Decrypt data
        // '9798D10A63E4E167122C4C07AF49C3A9'(hexa) -> "text to encrypt" (ascii)
        aes256_dec(data, &ctx);

        print_debug_msg("\nAES_256 Decryption Result:\n", data, 16);

}

// Make sure AES with IV and CBC is working
void test_aes256_cbc_iv(void)
{
        uint_farptr_t aes_desc_ptr;

        // 32 byte (256-bit) test key, for both AES_256 and HMAC_SHA1
        uint8_t test_key[AES_KEY_SIZE_BYTES] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};

        // 16 byte (128-bit) test IV for AES_256 w/CBC
        uint8_t test_IV[AES_IV_SIZE_BYTES] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

        // Data
        char data[64] = "this text to encrypt is exactly 3 blocks long!!1234567890123456";
        uint16_t data_blocks = 4;

        UART1_putstring("\nAES_256_CBC Key:\n");
        UART1_print_hex(test_key, AES_KEY_SIZE_BYTES);
        UART1_putstring("\nAES_256_CBC IV:\n");
        UART1_print_hex(test_IV, AES_IV_SIZE_BYTES);

        /*
        sprintf(result, "\nKey 5: %x%x%x%x%x\n", test_key[0],test_key[1],test_key[2],test_key[3],test_key[4]);
        UART1_putstring(result);
        UART1_putstring("\nAES_256_CBC Plaintext: \n");
        UART1_putstring(data);
        UART1_putstring("\n");
        */

        // Debug print
        print_debug_msg("\nAES_256_CBC Plaintext:\n", data, 64);

        /*
        sprintf(result, "\nStr addr 1: %p\n", &data);
        UART1_putstring(result);
        sprintf(result, "\nKey addr: %p\n", &test_key);
        UART1_putstring(result);
        sprintf(result, "\nIV addr: %p\n", &test_IV); 
        UART1_putstring(result);
        */

        // Initialize context
        bcal_cbc_ctx_t ctx;
        memset(&ctx, 0, sizeof(bcal_cbc_ctx_t));
        aes_desc_ptr = pgm_get_far_address(aes256_desc);
        bcal_cbc_init(aes_desc_ptr, test_key, 256, &ctx);

        // Encrypt data
        bcal_cbc_encMsg(test_IV, data, data_blocks, &ctx);
        
        /*
        // Data to hex
        int i;
        uint8_t temp[64];
        for (i = 0; i < 64; i++)
        {
           temp[i] = hexa_to_ascii(data[i]);
        }
        */

        // New hex print
        UART1_putstring("\nAES_256_CBC Cipertext:\n");
        UART1_print_hex(data, 64);

        // Debug print
        //print_debug_msg("\nAES_256_CBC Cipertext:\n", temp, 64);


        // Decrypt data
        bcal_cbc_decMsg(test_IV, data, data_blocks, &ctx);

        // Debug print
        print_debug_msg("\nAES_256_CBC Decryption Result:\n", data, 64);

        if(strncmp(data, "this text to encrypt is exactly 3 blocks long!!1234567890123456", 63) == 0)
            UART1_putstring("\n*** SUCCESS ***\n");
        else
        {
            UART1_putstring("\n*** ERROR ***\n");
            //for(int i = 0; i < 64; i++)
                //UART1_putchar(data[i]);
            UART1_putstring("\n*** DONE ***\n");
        }

        // No memory leaks today my friend!
        bcal_cbc_free(&ctx);
}

// Make sure HMAC SHA1 is working
void test_hmac_sha1(void)
{
    // 32 byte (256-bit) test key, for both AES_256 and HMAC_SHA1
    uint8_t test_key[AES_KEY_SIZE_BYTES] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};

    // Data to hash
    uint8_t data[69] = "this is the text to hash, must be at least 16 bytes (min block size)";
    uint32_t data_len_bits = (69*8);

    // Hash output buffer
    char hash_output[20];

    UART1_putstring("\nHMAC_SHA_1 Key:\n");
    UART1_print_hex(test_key, AES_KEY_SIZE_BYTES);
       
    print_debug_msg("\nMessage to Hash\n", data, 69);

    hmac_sha1(hash_output, test_key, AES_KEY_SIZE_BITS, data, data_len_bits);

    UART1_putstring("\nHMAC_SHA1 Hash:\n");
    UART1_print_hex(hash_output, 20);

}

/*
// Make sure HMAC SHA256 is working
void test_hmac_sha256(void)
{
    // 32 byte (256-bit) test key, for both AES_256 and HMAC_SHA256
    uint8_t test_key[AES_KEY_SIZE_BYTES] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};

    // Data to hash
    uint8_t data[69] = "this is the text to hash, must be at least 16 bytes (min block size)";
    uint32_t data_len_bits = (69*8);

    // Hash output buffer
    char hash_output[32];

    UART1_putstring("\nHMAC_SHA_256 Key:\n");
    UART1_print_hex(test_key, AES_KEY_SIZE_BYTES);
       
    print_debug_msg("\nMessage to Hash\n", data, 69);

    hmac_sha256(hash_output, test_key, AES_KEY_SIZE_BITS, data, data_len_bits);

    UART1_putstring("\nHMAC_SHA256 Hash:\n");
    UART1_print_hex(hash_output, 32);

}
*/

// Test reading chip serial number
void test_serial_read(void)
{
    //uint8_t ser_num[UNIQUE_SERIAL_BYTE_COUNT];
    //memcpy(ser_num, (void*)UNIQUE_SERIAL_ADDR, UNIQUE_SERIAL_BYTE_COUNT);

    //print_debug_msg("\nSerial number:\n", ser_num, UNIQUE_SERIAL_BYTE_COUNT);
}

// Test page size
void test_page_size(void)
{
    char result[1000];
    sprintf(result, "\nPage size hex: 0x%x, decimal %d\n", SPM_PAGESIZE, SPM_PAGESIZE);
    UART1_putstring(result);
}


