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

#include "sections.h"
#include "secret_management.h"

// 32 byte (256-bit) secret_key, for both AES_256 and HMAC_SHA1
uint8_t secret_key[AES_KEY_SIZE_BYTES] SECRETVAULT = { KEY_PLACEHOLDER_SENTINEL_123456 };

// Random seed baked during bootloader build
uint8_t bl_random_seed[RANDOM_SEED_SIZE_BYTES] SECRETVAULT = { RANDOM_SEED_PLACEHOLDER_SENTINEL_123456 };

