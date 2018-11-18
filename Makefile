#-------------------------------------------------------------------------
#
# Makefile for src/bin/pgcheck
#
# Copyright (c) 1998-2016, PostgreSQL Global Development Group
#
# src/bin/pgcheck/Makefile
#
#-------------------------------------------------------------------------

PGFILEDESC = "pgcheck - reads the data from pg_control"
#PGAPPICON=win32

subdir = src/bin/pgcheck
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global
CFLAGS+=-O0 -g3 -gstabs+

OBJS= pgcheck.o $(WIN32RES)

all: pgcheck

pgcheck: $(OBJS) | submake-libpgport
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(LDFLAGS_EX) $(LIBS) -g -O0 -o $@$(X)

install: all installdirs
	$(INSTALL_PROGRAM) pgcheck$(X) '$(DESTDIR)$(bindir)/pgcheck$(X)'

installdirs:
	$(MKDIR_P) '$(DESTDIR)$(bindir)'

uninstall:
	rm -f '$(DESTDIR)$(bindir)/pgcheck$(X)'

clean distclean maintainer-clean:
	rm -f pgcheck$(X) $(OBJS)

check:
	$(prove_check)

installcheck:
	$(prove_installcheck)
