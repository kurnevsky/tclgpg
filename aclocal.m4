# aclocal.m4 --
#
#	This file contains autoconf macros specific for TclGPG. It was
#	initially borrowed from
#	http://tcl.cvs.sourceforge.net/viewvc/*checkout*/tcl/sampleextension/
#	and modified.
#
# Copyright (c) 2008-2009 Sergei Golovan <sgolovan@nes.ru>
#
# See the file "license.terms" for information on usage and redistribution
# of this file, and for a DISCLAIMER OF ALL WARRANTIES.
#
# $Id$

#
# Include the TEA standard macro set
#

builtin(include,tclconfig/tcl.m4)

#------------------------------------------------------------------------
# LOCAL_AC_OUTPUT --
#
#	Specify one or more files. They are added to CONFIG_CLEAN_FILES
#	to be removed on make distclean, and passed to AC_OUTPUT macro.
#
# Arguments:
#	one or more file names
#
# Results:
#
#	Defines and substs the following vars:
#		PKG_TCL_SOURCES
#------------------------------------------------------------------------
AC_DEFUN([LOCAL_AC_OUTPUT], [
    CONFIG_CLEAN_FILES="$@"
    AC_SUBST(CONFIG_CLEAN_FILES)
    AC_OUTPUT($@)
])

