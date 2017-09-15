#
# Copyright 2017 The MITRE Corporation
#
# Modifications: Copywright 2017 Mark Horvath, Surbhi Shah, Tiemoko Ballo, Saurabh Sharma, Pouria Pezeshkian, Karthic Palaniappan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

# Hardware configuration settings.
MCU = atmega1284p
F_CPU = 20000000
BAUD = 115200

# Secret password default value.
PASSWORD ?= password

# Tool aliases.
CC = avr-gcc
STRIP  = avr-strip
OBJCOPY = avr-objcopy
PROGRAMMER = dragon_jtag

# Compiler configurations.
# Description of CDEFS options
# -g3 -- turns on  the highest level of debug symbols.
# -ggdb3 -- turns on the highest level of debug symbols for the gdb debugger.

CDEFS = -g3 -ggdb3 -mmcu=${MCU} -DF_CPU=${F_CPU} -DBAUD=${BAUD} -DRB_PASSWORD=\"${PASSWORD}\"
CLINKER = -Wl,-Map,bootloader.map \
          -Wl,--defsym=__heap_end=0x0 \
          -Wl,--gc-sections \
          -Wl,--relax \
          -Wl,--section-start=.bootloader_libs=0x00000 \
          -Wl,--section-start=.bootloader_funcs=0x01800 \
          -Wl,--section-start=.text=0x1e000 \
          -Wl,--section-start=.secret_vault=0x1fd00
CWARN =  -Wall -Wno-pointer-to-int-cast -Wno-pointer-sign
COPT = -std=gnu99 -Os -fno-tree-scev-cprop -mcall-prologues \
       -fno-inline-small-functions -fsigned-char -fdata-sections \
       -ffunction-sections

CFLAGS  = $(CDEFS) $(CLINKER) $(CWARN) $(COPT)

LIBS = crypto/

HOST_TOOLS=../host_tools

# Include file paths.
INCLUDES = -I./include -I./include/common -I./crypto/aes -I./crypto/gf256mul -I./crypto/sha1 -I./crypto/hmac-sha1 -I./crypto/sha256 -I./crypto/hmac-sha256 -I./crypto/bcal -I./crypto/memxor -I./crypto/misc

# Run clean even when all files have been removed.
.PHONY: clean

all:    flash.hex eeprom.hex
	@echo  Simple bootloader has been compiled and packaged as intel hex.

.PHONY: generate_secrets
generate_secrets: secrets/replace_script.sh secrets/key.txt secrets/randomseed.txt
	secrets/replace_script.sh
	sleep 3

secrets.o: generate_secrets
	$(CC) $(CFLAGS) $(INCLUDES) -c src/secrets.c

interrupts.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/interrupts.c

uart.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/uart.c

sys_startup.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/sys_startup.c

secret_management.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/secret_management.c

debug_tests.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/debug_tests.c

prng.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/prng.c

bootloader.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/bootloader.c

libcrypto.a:
	$(MAKE) -C crypto

bootloader_dbg.elf: libcrypto.a interrupts.o uart.o sys_startup.o secret_management.o bootloader.o secrets.o debug_tests.o prng.o
	$(CC) $(CFLAGS) $(INCLUDES) -o bootloader_dbg.elf interrupts.o uart.o sys_startup.o secret_management.o bootloader.o secrets.o debug_tests.o prng.o -L $(LIBS) -lcrypto

strip: bootloader_dbg.elf
# Create a version of the bootloder .elf file with all the debug symbols stripped.
	$(STRIP) bootloader_dbg.elf -o bootloader.elf

flash.hex: strip
	$(OBJCOPY) -R .eeprom -O ihex bootloader.elf flash.hex
	avr-size flash.hex
	avr-size -x -A bootloader.elf
	rm src/secrets.c

eeprom.hex: strip
	$(OBJCOPY) -j .eeprom --set-section-flags=.eeprom="alloc,load" --change-section-lma .eeprom=0 -O ihex bootloader.elf eeprom.hex

flash: $(HOST_TOOLS)/flash.hex $(HOST_TOOLS)/eeprom.hex $(HOST_TOOLS)/lfuse.hex $(HOST_TOOLS)/hfuse.hex $(HOST_TOOLS)/efuse.hex $(HOST_TOOLS)/lock.hex
	 avrdude  -P usb -p m1284p -c $(PROGRAMMER)  -u -U flash:w:$(HOST_TOOLS)/flash.hex:i \
						    -U eeprom:w:$(HOST_TOOLS)/eeprom.hex:i \
						    -U lfuse:w:$(HOST_TOOLS)/lfuse.hex:i \
						    -U hfuse:w:$(HOST_TOOLS)/hfuse.hex:i \
						    -U efuse:w:$(HOST_TOOLS)/efuse.hex:i \
						    -U lock:w:$(HOST_TOOLS)/lock.hex:i

debug: flash.hex eeprom.hex
	# Launch avarice: a tool that creates a debug server for the AVR and Dragon
	avarice -R -g :4242 &
	# Launch the avr debugger avr-gdb. The configuation for this tool is included 
	# in .gdbinit
	avr-gdb

clean:
	$(MAKE) clean -C crypto/
	$(RM) -v *.hex *.o *.elf $(MAIN)
	$(RM) src/secrets.c 

