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

#include <avr/interrupt.h>
#include <avr/io.h>

// Running overflow counter of clock ticks
volatile uint32_t uptime_tocks = 0;

// Counter increment callback
ISR(TIMER1_OVF_vect)
{
    uptime_tocks++;
}

// Start timer
void initialize_timer1(void)
{
    // Set pre-scaler to 1 (No pre-scale)
    TCCR1B |= (1 << CS10); 

    // Initialize timer1 to 0
    TCNT1 = 0;

    // Enable timer1 overflow interrupt
    TIMSK1 |= (1 << TOIE1);

    // Enable global interrupts
    sei();
}

