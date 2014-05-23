pamlibdir = $(PAMMODULEDIR)
pamlib_LTLIBRARIES = pam_bitid.la

noinst_HEADERS = baseX.h

pam_bitid_la_SOURCES = baseX.c pam_bitid.c
pam_bitid_la_LIBADD =  -lcrypto
pam_bitid_la_LDFLAGS = -L/usr/lib -no-undefined -avoid-version -module
pam_bitid_la_CFLAGS = -Wall -I../include
