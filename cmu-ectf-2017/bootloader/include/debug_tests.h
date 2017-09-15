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

#ifndef DEBUG_TESTS_H_
#define DEBUG_TESTS_H_

#include <stdio.h>
#include "uart.h"
#include "sections.h"
#include "pgmspace.h"
#include "aes.h"
#include "bcal_aes256.h" // Already includes aes.h!
#include "bcal-cbc.h"
#include "sha1.h"
#include "hmac-sha1.h"
#include "secret_management.h"
//#include "sha256.h"
//#include "hmac-sha256.h"

void UART1_putstring_P(const char *str);
void print_debug_msg(char *header, uint8_t *data, uint8_t data_len);
void test_aes256_basic(void) BOOTLOADERLIBS;
void test_aes256_cbc_iv(void) BOOTLOADERLIBS;
void test_hmac_sha1(void) BOOTLOADERLIBS;
//void test_hmac_sha256(void) BOOTLOADERLIBS;
void test_serial_read(void);
void test_page_size(void);

#endif /* DEBUG_TESTS_H_  */
