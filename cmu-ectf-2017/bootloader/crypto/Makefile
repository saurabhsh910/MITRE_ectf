############################################
#
#  Makefile to compile the AES256 libraries
#
############################################

TARGET=main

# Here all the dirs to include to find .h files
DIR= .
DIR+= aes/
DIR+= bcal/
DIR+= misc/
DIR+= gf256mul/
DIR+= memxor/
DIR+= sha256/
DIR+= hmac-sha256/
DIR+= sha1/
DIR+= hmac-sha1/

# C source files
SRC= aes/aes_dec.c
SRC+= aes/aes_enc.c
SRC+= aes/aes_sbox.c
SRC+= aes/aes_invsbox.c
SRC+= aes/aes_keyschedule.c
SRC+= aes/aes256_enc.c
SRC+= aes/aes256_dec.c
SRC+= bcal/bcal_aes256.c
SRC+= bcal/bcal-cbc.c
SRC+= bcal/bcal-basic.c
SRC+= sha1/sha1.c
SRC+= hmac-sha1/hmac-sha1.c
SRC+= sha256/sha256.c
SRC+= hmac-sha256/hmac-sha256.c
SRC+= misc/keysize_descriptor.c

# Here ASM source files, Make them always end in a capital 'S', ex: asmfile.S
ASRC= gf256mul/gf256mul.S
ASRC+= memxor/memxor.S

# TODO: If C source works, try replacing - increased speed? (bootloader.elf size tested - 8.8k C code vs 8.6k ASM)
#ASRC+= misc/avr-asm-macros.S
#ASRC+= aes/aes_enc-asm.S
#ASRC+= aes/aes_aleph_enc-asm.S
#ASRC+= aes/aes_dec-asm.S
#ASRC+= aes/aes_invsbox-asm.S
#ASRC+= aes/aes_sbox-asm.S
#ASRC+= aes/aes_keyschedule-asm.S
#ASRC+= aes/aes_aleph_keyschedule-asm.S

# frequency in hz
F_CPU = 20000000

# Microcontroller to be used
MCU=atmega1284p

# Optimization 1, 2, 3 and s for size
OPT = s

# You should not have to change anything below here

# Here we add the prefix -I for the compiler ex: '-I ../dir/subdir/'
IDIR = ${addprefix -I , $(DIR)}
IDIR += ${addprefix -I, ../include/common/}

# Compiler C flags
CFLAGS = -mmcu=$(MCU) -DF_CPU=$(F_CPU)UL -O$(OPT) -ffunction-sections -fdata-sections -Wno-pointer-to-int-cast
LDFLAGS = -Wl --gc-sections

# Compiler
CC      = avr-gcc
AR      = avr-ar
OBJCOPY = avr-objcopy
SIZE    = avr-size

# C files and ASM files to object files
OBJ = $(SRC:%.c=%.o) $(ASRC:%.S=%.o)

all: libcrypto.a

clean:
	rm -rf *.o *.hex *.elf $(OBJ) *.a

# Compile: create object files from C and ASM source files.
%.o: %.c
	$(CC) $(CFLAGS) $(IDIR) -c $< -o $@

%.o: %.S
	$(CC) $(CFLAGS) $(IDIR) -c $< -o $@

libcrypto.a: $(OBJ)
	avr-ar rcs libcrypto.a $(OBJ)
	ranlib libcrypto.a
