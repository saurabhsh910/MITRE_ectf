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
 * UART configuration headers.
 */


#ifndef UART_H_
#define UART_H_

#include <stdbool.h>

void UART1_init(void);

void UART1_putchar(unsigned char data);

bool UART1_data_available(void);
unsigned char UART1_getchar(void);

void UART1_flush(void);

void UART1_putstring(char* str);


void UART0_init(void);

void UART0_putchar(unsigned char data);

bool UART0_data_available(void);
unsigned char UART0_getchar(void);

void UART0_flush(void);

void UART0_putstring(char* str);
char hexa_to_ascii(uint8_t input);

void UART0_print_hex(unsigned char *str, unsigned int len);
void UART1_print_hex(unsigned char *str, unsigned int len);

#endif /* UART_H_ */
