ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = 1.9 foreign dist-bzip2

SUBDIRS = src tests

CLEANFILES = 

EXTRA_DIST = examples releases autogen.sh README.md TODO.md

builddeb:
	dch -e
	dpkg-buildpackage -us -uc
