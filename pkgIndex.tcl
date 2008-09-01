# pkgIndex.tcl --
#
#       This file is part of the TclGPG library. It registers gpg package
#       for Tcl.
#
# Copyright (c) 2008 Sergei Golovan <sgolovan@nes.ru>
#                    Antoni Grzymala <antoni@chopin.edu.pl>
#
# See the file "license.terms" for information on usage and redistribution
# of this file, and for a DISCLAMER OF ALL WARRANTIES.
#
# $Id$

package ifneeded gpg 1.0 [list source [file join $dir tclgpg.tcl]]

# vim:ts=8:sw=4:sts=4:et
