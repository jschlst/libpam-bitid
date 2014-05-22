ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = 1.9 foreign dist-bzip2

SUBDIRS = src tests

CLEANFILES = 

EXTRA_DIST = examples releases

builddeb:
	dch -e
	dpkg-buildpackage -us -uc
