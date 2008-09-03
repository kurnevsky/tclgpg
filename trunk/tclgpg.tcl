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
    variable gpgExecutable /usr/bin/gpg

    if {[catch {exec $gpgExecutable --version} msg] || \
            ![string equal -length 12 $msg "gpg (GnuPG) "]} {

        # Destory the current namespace if it contains nothing except
        # the gpgExecutable variable. Otherwise it contains user data,
        # so it must be preserved.

        if {[llength [info vars [namespace current]::*]] == 1 && \
                [llength [info procs [namespace current]::*]] == 0} {
            namespace delete [namespace current]
        } else {
            unset gpgExecutable
        }

        return -code error "GnuPG binary is unusable"
    }

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
            return -code error "Missing operation"
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
        start-trustitem -
        next-trustitem  -
        done-trustitem  -
        info-trustitem  {
            return -code error \
                   "GPG doesn't support --list-trust-path option"
        }
        default {
            return -code error \
                   [format "Illegal operation \"%s\"" $opts(-operation)]
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
    upvar 0 $keystoken keys

    catch {unset keys}
    array set keys {}

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

    Parse keys $gpgOutput
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

    foreach {key val} $args {
        switch -- $key {
            -operation {}
            -key {
                set fingerprint $val
            }
            default {
                return -code error \
                    [format "bad switch \"%s\": must be -operation or -key" \
                            $key]
            }
        }
    }

    variable $state(keystoken)
    upvar 0 $state(keystoken) keys

    if {[::info exists keys($fingerprint)]} {
        return $keys($fingerprint)
    } else {
        return -code error "Invalid Value"
    }
}

proc ::gpg::Parse {keysVar gpgOutput} {
    upvar 1 $keysVar keys

    set key {}
    foreach line [split $gpgOutput "\n"] {
        set fields [split $line ":"]
        switch -- [lindex $fields 0] {
            pub -
            sec -
            crt -
            crs {
                # Store the current key and start a new one
                array set tmp $key
                if {[::info exists tmp(fingerprint)]} {
                    set keys($tmp(fingerprint)) $key
                }
                array unset tmp
                set key {}
            }
            sub -
            ssb {
                # Start a new subkey
            }
            sig {
                # Signature
            }
        }
        set key [concat $key [ParseRecord $fields]]
    }

    # Store the last key
    array set tmp $key
    if {[::info exists tmp(fingerprint)]} {
        set keys($tmp(fingerprint)) $key
    }

    return
}

proc ::gpg::ParseRecord {fields} {
    switch -- [lindex $fields 0] {
	pub -
	sec -
        crt -
        crs {
            # pub: public key
            # sec: secret key
            # crt: X.509 certificate
            # crs: X.509 certificate and private key available
            set result [Trust [lindex $fields 1]]
            lappend result length    [lindex $fields 2]
            lappend result algorithm [Algorithm [lindex $fields 3]]
            lappend result keyid     [lindex $fields 4]
            lappend result created   [lindex $fields 5]
            if {![string equal [lindex $fields 6] ""]} {
                lappend result expire [lindex $fields 6]
            }
            # TODO
            lappend result owner-trust [lindex $fields 8]
            # TODO
            lappend result key-capability [lindex $fields 11]
            return $result
        }
	sub {
            # subkey (secondary key)
        }
	ssb {
            # secret subkey (secondary key)
        }
	uid {
            # user id (only field 10 is used)
            set userid [string map {\\x3a :} [lindex $fields 9]]
            if {[regexp {^(.*\S)\s*\((.*)\)\s*<(.*)>$} $userid -> \
                        name comment email]} {
                return [list userid $userid name $name comment $comment \
                             email $email]
            } elseif {[regexp {^(.*\S)\s*<(.*)>$} $userid -> \
                              name email]} {
                return [list userid $userid name $name email $email]
            } else {
                return [list userid $userid]
            }
        }
	uat {
            # user attribute (same as user id except for field 10)
        }
        sig {
            # signature
        }
        rev {
            # revocation signature
        }
	fpr {
            # fingerprint: (fingerprint is in field 10)
            set fingerprint [lindex $fields 9]
            return [list fingerprint $fingerprint]
        }
	pkd {
            # public key data (special field format)
        }
        grp {
            # reserved for gpgsm
        }
        rvk {
            # revocation key
        }
        tru {
            # trust database information
        }
        spk {
            # signature subpacket
        }
        default {
            return {}
        }
    }
}

proc ::gpg::Trust {code} {
    switch -- $code {
	o {
            # Unknown (this key is new to the system)
            return {validity unknown}
        }
        i {
            # The key is invalid (e.g. due to a missing self-signature)
            return {key-invalid 1}
        }
	d {
            # The key has been disabled
	    # (deprecated - use the 'D' in field 12 instead)
            return {key-disabled 1}
        }
	r {
            # The key has been revoked
            return {key-revoked 1}
        }
	e {
            # The key has expired
            return {key-expired 1}
        }
	- {
            # Unknown trust (i.e. no value assigned)
            return {validity unknown}
        }
	q {
            # Undefined trust
	    # '-' and 'q' may safely be treated as the same
	    # value for most purposes
            return {validity undefined}
        }
	n {
            # Don't trust this key at all
            return {validity never}
        }
	m {
            # There is marginal trust in this key
            return {validity marginal}
        }
	f {
            # The key is fully trusted
            return {validity full}
        }
	u {
            # The key is ultimately trusted.  This often means
	    # that the secret key is available, but any key may
	    # be marked as ultimately trusted.
            return {validity ultimate}
        }
    }
}

proc ::gpg::Algorithm {code} {
    switch -- $code {
 	1 -
        2 -
        3 {
            # RSA
            return RSA
        }
	16 {
            # Elgamal (encrypt only)
            return ElG
        }
	17 {
            # DSA (sometimes called DH, sign only)
            return DSA
        }
	20 {
            # Elgamal (sign and encrypt - don't use them!)
            return ElG
        }
        default {
            return Unknown
        }
    }
}

proc ::gpg::ExecGPG {args} {
    variable gpgExecutable

    set fd [open |[linsert $args 0 $gpgExecutable]]

    # Gpg output is in UTF-8 encoding, so fconfigureing the channel.
    # TODO: Asynchronous processing (non-blocking channel)

    fconfigure $fd -encoding utf-8
    set data [read $fd]

    # If gpg returns nonzero status or writes to stderr, close raises
    # an error. So, the catch is necessary.
    # TODO: Process the error

    catch {close $fd}
    return $data
}

# vim:ts=8:sw=4:sts=4:et
