# Bradford Smith (bsmith8)
# Makefile for CS 579 Lab 1
# 04/04/2016
# "I pledge my honor that I have abided by the Stevens Honor System."
################################################################################

# Project variables
AUTHOR = bsmith8
PROJECT = cs579-lab1
TARBALL = ../$(AUTHOR)_$(PROJECT).tar.gz
RM = rm -f
TAR = tar -cvzf

# Executable names
ENC = pv_encrypt
DEC = pv_decrypt
GEN = pv_keygen

# Compiler, flags, etc.
CC = gcc
DEBUG = -g -O2
WFLAGS = -ansi -Wall -Wsign-compare -Wchar-subscripts -Werror
LDFLAGS = -Wl,-rpath,/usr/lib

# Libraries against which the object file for each utility should be linked
INCLUDES = /usr/include/
LIBS = /usr/lib/
DCRYPTINCLUDE = /home/nicolosi/devel/libdcrypt/include/
DCRYPTLIB = /home/nicolosi/devel/libdcrypt/lib/
DMALLOC = #-ldmalloc
GMP = -lgmp
DCRYPT = -ldcrypt

# group all includes and all libs into variables to make targets shorter
ALLINCLUDES = -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE)
ALLLIBS = -L. -L$(LIBS) -L$(DCRYPTLIB)
ALLINCLLIBS = $(DCRYPT) $(DMALLOC) $(GMP)

# The source file(s) for each program
all: $(GEN) $(ENC) $(DEC)

pv_misc.o: pv_misc.c pv.h
	$(CC) $(DEBUG) $(WFLAGS) $(ALLINCLUDES) -c pv_misc.c

pv_keygen.o: pv_keygen.c pv_misc.c pv.h
	$(CC) $(DEBUG) $(WFLAGS) $(ALLINCLUDES) -c pv_keygen.c pv_misc.c

pv_encrypt.o: pv_encrypt.c pv_misc.c pv.h
	$(CC) $(DEBUG) $(WFLAGS) $(ALLINCLUDES) -c pv_encrypt.c pv_misc.c

pv_decrypt.o: pv_decrypt.c pv_misc.c pv.h
	$(CC) $(DEBUG) $(WFLAGS) $(ALLINCLUDES) -c pv_decrypt.c pv_misc.c

pv_keygen: pv_keygen.o pv_misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $^ $(ALLLIBS) $(ALLINCLLIBS)

pv_encrypt: pv_encrypt.o pv_misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $^ $(ALLLIBS) $(ALLINCLLIBS)

pv_decrypt: pv_decrypt.o pv_misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $^ $(ALLLIBS) $(ALLINCLLIBS)

clean:
	-$(RM) *.o
	-$(RM) *~
	-$(RM) core
	-$(RM) *.core

# full clean
fclean: clean
	-$(RM) $(ENC)
	-$(RM) $(DEC)
	-$(RM) $(GEN)

# remake
re: fclean all

# make a tarball (for submission)
tar: fclean
	$(TAR) $(TARBALL) ./*

.PHONY: all clean fclean
