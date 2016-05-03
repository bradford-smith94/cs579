# Bradford Smith (bsmith8)
# Makefile for CS 579 Lab 2
# 05/03/2016
# "I pledge my honor that I have abided by the Stevens Honor System."
################################################################################

# Project variables
AUTHOR = bsmith8
PROJECT = cs579-lab2
TARBALL = ../$(AUTHOR)_$(PROJECT).tar.gz
RM = rm -f
TAR = tar -cvzf

# Executable names
PKI = skgu_pki
NIDH = skgu_nidh

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
all: $(PKI) $(NIDH)

pv_misc.o : pv_misc.c pv.h
	$(CC) $(DEBUG) $(WFLAGS) $(ALLINCLUDES) -c pv_misc.c

skgu_misc.o : skgu_misc.c skgu.h
	$(CC) $(DEBUG) $(WFLAGS) $(ALLINCLUDES) -c skgu_misc.c

skgu_cert.o : skgu_cert.c skgu.h pv.h
	$(CC) $(DEBUG) $(WFLAGS) $(ALLINCLUDES) -c skgu_cert.c

skgu_pki.o : skgu_pki.c skgu.h pv.h
	$(CC) $(DEBUG) $(WFLAGS) $(ALLINCLUDES) -c skgu_pki.c

skgu_pki : skgu_pki.o skgu_cert.o skgu_misc.o pv_misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $^ $(ALLLIBS) $(ALLINCLLIBS)

skgu_nidh.o : skgu_nidh.c skgu.h pv.h
	$(CC) $(DEBUG) $(WFLAGS) $(ALLINCLUDES) -c skgu_nidh.c

skgu_nidh : skgu_nidh.o skgu_cert.o skgu_misc.o pv_misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $^ $(ALLLIBS) $(ALLINCLLIBS)

test: re
	./$(PKI) init
	./$(PKI) cert -g alice.priv alice.pub alice
	./$(PKI) cert -g bob.priv bob.pub bob
	./$(NIDH) alice.priv alice.cert alice bob.pub bob.cert bob example
	./$(NIDH) bob.priv bob.cert bob alice.pub alice.cert alice example
	diff example-alice.b64 example-bob.b64


clean:
	-$(RM) *.o
	-$(RM) *~
	-$(RM) core
	-$(RM) *.core

# full clean
fclean: clean
	-$(RM) -r .pki
	-$(RM) *.cert
	-$(RM) *.priv
	-$(RM) *.pub
	-$(RM) $(PKI)
	-$(RM) $(NIDH)

# remake
re: fclean all

# make a tarball (for submission)
tar: fclean
	$(TAR) $(TARBALL) ./*

.PHONY: all clean fclean
