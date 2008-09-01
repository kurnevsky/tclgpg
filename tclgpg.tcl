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
    variable operations [list info cancel wait get set encrypt decrypt sign \
                              verify start-key next-key done-key info-key \
                              start-trustitem next-trustitem done-trustitem \
                              info-trustitem]

    variable properties [list protocol armor textmode number-of-certs \
                              keylistmode passphrase-callback \
                              progress-callback idle-callback signers]
}

# ::gpg::info --
#

proc ::gpg::info {args} {
    switch -- [llength $args] {
        0 {
            return [list datatypes signature-status signature-modes \
                         attributes validity capabilities protocols \
                         keylist-modes]
        }
        1 {
            set option [lindex $args 0]
            switch -- $option {
                datatypes {
                    return [list none mem fd file cb]
                }
                signature-status {
                    return [list none good bad nokey nosig error diff \
                                 expired expiredkey]
                }
                signature-modes {
                    return [list valid green red key-revoked key-expired \
                                 signature-expired key-missing crl-missing \
                                 crl-too-old bad-policy sys-error]
                }
                attributes {
                    return [list keyid fingerprint algorithm length created \
                                 expires owner-trust userid name email comment \
                                 validity level type is-secret key-revoked \
                                 key-invalid uid-revoked uid-invalid \
                                 key-capability key-expired key-disabled \
                                 serial issuer chainid signature-status \
                                 error-token signature-summary]
                }
                validity {
                    return [list unknown undefined never marginal full ultimate]
                }
                capabilities {
                    return [list encrypt sign certify]
                }
                protocols {
                    return [list openpgp cms auto]
                }
                keylist-modes {
                    return [list local extern sigs]
                }
                default {
                    return -code error \
                           [format "bad option \"%s\": must be datatypes,\
                                    signature-status, signature-modes,\
                                    attributes, validity, capabilities,\
                                    protocols, or keylist-modes" $option]
                }
            }
        }
        default {
            return -code error [format "usage: %s option" [lindex [::info level 0] 0]]
        }
    }
}

# ::gpg::context --
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

proc ::gpg::context {} {
    variable id

    if {![::info exists id]} {
        set id 0
    }

    set token [namespace current]::gpg[incr id]
    variable $token
    upvar 0 $token state

    set state(id) $id

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

    if {[::info exists state(keystoken)]} {
        set keystoken $state(keystoken)
        variable $keystoken
        upvar 0 $keystoken keys
        unset keys
        unset state(keystoken)
    }

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

    if {![::info exists opts(-operation)]} {
            return -code error -errorinfo "Missing operation"
    }

    switch -- $opts(-operation) {
        info      { return [eval [list Info     $token] $args] }
        cancel    { return [eval [list Cancel   $token] $args] }
        wait      { return [eval [list Wait     $token] $args] }
        get       { return [eval [list Get      $token] $args] }
        set       { return [eval [list Set      $token] $args] }
        start-key { return [eval [list StartKey $token] $args] }
        next-key  { return [eval [list NextKey  $token] $args] }
        done-key  { return [eval [list DoneKey  $token] $args] }
        info-key  { return [eval [list InfoKey  $token] $args] }
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

    if {![::info exists opts(-property)]} {
        return [linsert $properties end last-op-info]
    } else {
        return $state($opts(-property))
    }
}

proc ::gpg::Set {token args} {
    variable properties
    variable $token
    upvar 0 $token state

    array set opts $args

    if {![::info exists opts(-property)]} {
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

proc ::gpg::StartKey {token args} {
    variable $token
    upvar 0 $token state

    if {[::info exists state(searchid)]} {
        return -code error \
               "already doing a key listing, end that one first"
    }

    set patterns {}
    set operation --list-keys

    foreach {key val} $args {
        switch -- $key {
            -operation {}
            -patterns {
                if {[string first < $val] >= 0 || \
                        [string first > $val] >= 0 || \
                        [string first | $val] >= 0} {
                    # Patterns will go to [exec] call, so filter dangerous
                    # symbols.
                    return -code error \
                           "illegal symbol \"<\", \">\", or \"|\" in patterns"
                }
                set patterns $val
            }
            -secretonly {
                if {[string is true -strict $val]} {
                    set operation --list-secret-keys
                } elseif {![string is false -strict $val]} {
                    return -code error \
                           [format "expected boolean value but got \"%s\"" \
                                   $val]
                }
            }
            default {
                return -code error \
                       [format "bad switch \"%s\": must be -operation,\
                                -patterns, or -secretonly" $key]
            }
        }
    }

    set keystoken [namespace current]::keys$state(id)
    variable $keystoken

    set state(keystoken) $keystoken

    set gpgOutput [eval [list ExecGPG --batch \
                           --comment "" \
                           --no-tty \
                           --charset utf8 \
                           --with-colons \
                           --fixed-list-mode \
                           --with-fingerprint \
                           --with-fingerprint \
                           $operation --] $patterns]

    Parse $keystoken $gpgOutput
    set state(searchid) [array startsearch $keystoken]

    return
}

proc ::gpg::NextKey {token args} {
    variable $token
    upvar 0 $token state

    if {![::info exists state(searchid)]} {
        return -code error "not doing a key listing"
    }

    return [array nextelement $state(keystoken) $state(searchid)]
}

proc ::gpg::DoneKey {token args} {
    variable $token
    upvar 0 $token state

    if {![::info exists state(searchid)]} {
        return -code error "not doing a key listing"
    }

    array donesearch $state(keystoken) $state(searchid)
    unset state(searchid)
    return
}

proc ::gpg::InfoKey {token args} {
    variable $token
    upvar 0 $token state

    # TODO
}

proc ::gpg::Parse {keystoken gpgOutput} {
    # TODO
}

proc ::gpg::ExecGPG {args} {
    # TODO: catch errors
    set fd [open |[linsert $args 0 gpg]]
    set data [read $fd]
    close $fd
    return $data
}

# vim:ts=8:sw=4:sts=4:et
