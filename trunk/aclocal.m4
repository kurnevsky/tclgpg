#
# Include the TEA standard macro set
#

builtin(include,tclconfig/tcl.m4)

#
# Add here whatever m4 macros you want to define for your package
#

#------------------------------------------------------------------------
# TEA_ADD_TCL_SOURCES --
#
#	Specify one or more Tcl source files.  These should be platform
#	independent runtime files.
#
# Arguments:
#	one or more file names
#
# Results:
#
#	Defines and substs the following vars:
#		PKG_TCL_SOURCES
#------------------------------------------------------------------------
AC_DEFUN([TEA_ADD_TCL_SOURCES], [
    vars="$@"
    for i in $vars; do
	# check for existence, be strict because it is installed
	if test ! -f "${srcdir}/$i" -a ! -f "${srcdir}/$i.in" ; then
	    AC_MSG_ERROR([could not find tcl source file '${srcdir}/$i' or '${srcdir}/$i.in'])
	fi
	PKG_TCL_SOURCES="$PKG_TCL_SOURCES $i"
    done
    AC_SUBST(PKG_TCL_SOURCES)
])

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

