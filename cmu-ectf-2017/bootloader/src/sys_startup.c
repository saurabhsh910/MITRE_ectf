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

#include <avr/io.h>
#include <avr/wdt.h>

void __Init         (void) __attribute__ ((naked)) __attribute__ ((section (".init0")));
void __jumpMain     (void) __attribute__ ((naked)) __attribute__ ((section (".init9")));

void __Init(void)
{
#if 0
    // init stack here, bug in WinAVR 20071221 does not init stack based on __stack
    __asm__ __volatile__
    (
        ".set __stack, %0    \n\t"
        "ldi r24, %1        \n\t"
        "ldi r25, %2        \n\t"
        "out __SP_H__, r25    \n\t"
        "out __SP_L__, r24    \n\t"

                /* GCC depends on register r1 set to zero */
        "clr __zero_reg__    \n\t"
        :
        : "i" (RAMEND), "M" (RAMEND & 0xff), "M" (RAMEND >> 8)
    );

    // set SREG to 0
    SREG = 0;

    // set extended indirect jump high address
    #ifdef EIND
        EIND = 1;
    #endif
#endif

    //-------------------------------------------------------------------
    //     Turn off Watchdog Timer
    //-------------------------------------------------------------------

    // Clear wdt reset flag - needed for enhanced wdt devices
    #if defined(MCUCSR)
        MCUCSR = 0;
    #elif defined(MCUSR)
        MCUSR = 0;
    #endif
	uint8_t temp;
	temp = MCUCR;
	MCUCR = temp | (1 << IVCE);
	MCUCR = temp | (1 << IVSEL);

    __asm__ __volatile__
    (
        "ldi r24, %0            \n\t"
        "sts %1, r24            \n\t"
        "sts %1, __zero_reg__    \n\t"

        /* Jump over our data section */
        "rjmp __do_copy_data    \n\t"
        :
        : "M" ((1<<_WD_CHANGE_BIT) | (1<<WDE)),    "M" (_SFR_MEM_ADDR(_WD_CONTROL_REG))
    );
}

void __jumpMain(void)
{
    // jump to main()
    asm volatile ( "rjmp main");
}
