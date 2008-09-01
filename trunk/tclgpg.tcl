# tclgpgme.tcl --
#        Tcl interface to GNU Privacy Guard.
#
# Copyright (c) 2008 Sergei Golovan <sgolovan@nes.ru>,
#                    Antoni Grzymala <antoni@chopin.edu.pl>
#
# See the file "license.terms" for information on usage and redistribution
# of this file, and for a DISCLAMER OF ALL WARRANTIES.
#
# $Id$

package provide gpg 1.0

namespace eval ::gpg {
    variable operations [list cancel wait get set info ...]

    variable properties [list protocol \
                              armor \
                              textmode \
                              keylistmode \
                              passphrase-callback \
                              signers]
}

# ::gpg::new --
#
#       Create a new GPG context token.
#
# Arguments:
#       None.
#
# Result:
#       A context token (which is used as a procedure).
#
# Side effects:
#       A new procedure and a state variable are created. Also deleting of
#       the procedure is traced to unset the state variable.

proc ::gpg::new {} {
    variable id

    if {![info exists id]} {
        set id 0
    }

    set token [namespace current]::gpg[incr id]
    variable $token
    upvar 0 $token state

    proc $token {args} "eval {[namespace current]::Exec} {$token} \$args"

    trace add command $token delete [namespace code [list Free $token]]

    return $token
}

# ::gpg::Free --
#
#       Unset state variable corresponding to a context token.
#
# Arguments:
#       token       A GPG context token created in ::gpg::new.
#       args        (unused) Arguments added by trace.
#
# Result
#       An empty string.
#
# Side effects:
#       A state variable is destroyed.

proc ::gpg::Free {token args} {
    variable $token
    upvar 0 $token state

    catch {unset state}
    return
}

# ::gpg::Exec --
#
#       Execute a GPG context operation. This procedure is invoked when a user
#       calls [$token -operation ...].
#
# Arguments:
#       token       A GPG context token created in ::gpg::new.
#       args        Arguments serialized array. It must contain pair
#                   -operation <op>. The other arguments are operation-
#                   dependent.
#
# Result:
#       The result of a corresponding operation.
#
# Side effects:
#       The side effects of a corresponding operation.

proc ::gpg::Exec {token args} {
    variable properties
    variable $token
    upvar 0 $token state

    array set opts $args

    if {![info exists opts(-operation)]} {
            return -code error -errorinfo "Missing operation"
    }

    switch -- $opts(-operation) {
        cancel { return [eval [list Cancel $token] $args] }
        wait   { return [eval [list Wait   $token] $args] }
        get    { return [eval [list Get    $token] $args] }
        set    { return [eval [list Set    $token] $args] }
        info   { return [eval [list Info   $token] $args] }
        default {
            return -code error \
                   -errorinfo [format "Illegal operation \"%s\"" \
                                      $opts(-operation)]
        }
    }
}

proc ::gpg::Cancel {token args} {
    # TODO
}

proc ::gpg::Wait {token args} {
    # TODO
}

proc ::gpg::Get {token args} {
    variable properties
    variable $token
    upvar 0 $token state

    array set opts $args

    if {![info exists opts(-property)]} {
        return $properties
    } else {
        return $state($opts(-property))
    }
}

proc ::gpg::Set {token args} {
    variable properties
    variable $token
    upvar 0 $token state

    array set opts $args

    if {![info exists opts(-property)]} {
        return $properties
    } else {
        set state($opts(-property)) $opts(-value)
        return
    }
}

proc ::gpg::Info {token args} {
    variable operations

    return $operations
}

# vim:ts=8:sw=4:sts=4:et
