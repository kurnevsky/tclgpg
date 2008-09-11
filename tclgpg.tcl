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

package require Tcl 8.4

if {![package vsatisfies [package require Tcl] 8.6]} {
    package require Tclx
}

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

    variable validities [list unknown undefined never marginal full ultimate]

    # Variable to store public keys
    variable keys

    variable debug 2
}

# ::gpg::info --
#

proc ::gpg::info {args} {
    variable validities

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
                                 expired expiredkey revokedkey]
                }
                signature-modes {
                    return [list normal detach clear]
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
                    return $validities
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
#       token       A GPG context token created in ::gpg::context.
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
#       token       A GPG context token created in ::gpg::context.
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
    set newArgs {}
    foreach {key val} $args {
        switch -- $key {
            -operation { set op $val }
            default { lappend newArgs $key $val }
        }
    }

    if {![::info exists op]} {
        return -code error "Missing operation"
    }

    switch -- $op {
        info      { set res [eval [list Info     $token] $newArgs] }
        cancel    { set res [eval [list Cancel   $token] $newArgs] }
        wait      { set res [eval [list Wait     $token] $newArgs] }
        get       { set res [eval [list Get      $token] $newArgs] }
        set       { set res [eval [list Set      $token] $newArgs] }
        start-key { set res [eval [list StartKey $token] $newArgs] }
        next-key  { set res [eval [list NextKey  $token] $newArgs] }
        done-key  { set res [eval [list DoneKey  $token] $newArgs] }
        info-key  { set res [eval [list InfoKey  $token] $newArgs] }
        encrypt   { set res [eval [list Encrypt  $token] $newArgs] }
        sign      { set res [eval [list Sign     $token] $newArgs] }
        verify    { set res [eval [list Verify   $token] $newArgs] }
        decrypt   { set res [eval [list Decrypt  $token] $newArgs] }
        start-trustitem -
        next-trustitem  -
        done-trustitem  -
        info-trustitem  {
            return -code error \
                   "GPG doesn't support --list-trust-path option"
        }
        default {
            return -code error [format "Illegal operation \"%s\"" $op]
        }
    }

    set state(last-op-info) $op
    return $res
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

    set gproperties [linsert $properties end last-op-info]

    array set opts $args

    if {![::info exists opts(-property)]} {
        return $gproperties
    } elseif {[lsearch -exact $gproperties $opts(-property)] >= 0} {
        if {[::info exists state($opts(-property))]} {
            return $state($opts(-property))
        } else {
            return ""
        }
    } else {
        return -code error [format "unknown property \"%s\"" $opts(-property)]
    }
}

proc ::gpg::Set {token args} {
    variable properties
    variable $token
    upvar 0 $token state

    array set opts $args

    if {![::info exists opts(-property)]} {
        return $properties
    } elseif {[lsearch -exact $properties $opts(-property)] >= 0} {
        set state($opts(-property)) $opts(-value)
        return
    } else {
        return -code error [format "unknown property \"%s\"" $opts(-property)]
    }
}

proc ::gpg::Info {token args} {
    variable operations

    return $operations
}

proc ::gpg::Decrypt {token args} {
    variable $token
    upvar 0 $token state

    foreach {key val} $args {
        switch -- $key {
            -input { set input $val }
            -checkstatus { set checkstatus $val }
        }
    }

    set name_fd [TempFile]
    foreach {filename fd} $name_fd break

    puts $fd $input
    close $fd

    set res [eval [list ExecGPG $token decrypt "" \
                                --no-tty \
                                --status-fd 2 \
                                --logger-fd 2 \
                                --command-fd 0 \
                                --no-verbose \
                                --output - \
                                --decrypt] \
                                -- $filename]
    file delete -force -- $filename
    return $res
}

proc ::gpg::Verify {token args} {
    variable $token
    upvar 0 $token state

    foreach {key val} $args {
        switch -- $key {
            -signature { set signature $val }
            -input { set input $val }
        }
    }

    if {[::info exists input]} {
        set op dverify
        # A signature is detached, so create a temporary file
        # with a signature.
        set params {--enable-special-filenames --verify}

        set name_fd [TempFile]
        foreach {filename fd} $name_fd break

        puts $fd $signature
        close $fd

        set fnames [list $filename -]
    } else {
        set op verify
        set params {}
        set fnames {}
        set input $signature
    }

    set res [eval [list ExecGPG $token $op $input \
                                --no-tty \
                                --status-fd 2 \
                                --logger-fd 2 \
                                --command-fd 0 \
                                --no-verbose \
                                --output -] \
                                $params \
                                -- $fnames]
    if {[::info exists filename]} {
        file delete -force -- $filename
    }
    Debug 2 $res
    return $res
}

proc ::gpg::Sign {token args} {
    variable $token
    upvar 0 $token state

    set mode normal
    foreach {key val} $args {
        switch -- $key {
            -input { set input $val }
            -mode { set mode $val }
        }
    }

    set armor [Get $token -property armor]
    if {![string equal $armor ""] && $armor} {
        set params {--armor}
    } else {
        set params {}
    }

    switch -- $mode {
        normal { lappend params --sign }
        detach { lappend params --detach-sign }
        clear { lappend params --clearsign }
    }

    array set tmp {}
    foreach key [Get $token -property signers] {
        array unset tmp
        array set tmp [InfoKey $token -key $key]
        lappend params -u $tmp(keyid)
    }

    return [eval [list ExecGPG $token sign $input \
                               --no-tty \
                               --status-fd 2 \
                               --logger-fd 2 \
                               --command-fd 0 \
                               --no-verbose \
                               --output -] \
                               $params \
                               --]
}

proc ::gpg::Encrypt {token args} {
    variable $token
    upvar 0 $token state

    set sign false
    foreach {key val} $args {
        switch -- $key {
            -input { set input $val }
            -recipients { set recipients $val }
            -sign { set sign $val }
        }
    }

    set armor [Get $token -property armor]
    if {![string equal $armor ""] && $armor} {
        set params {--armor}
    } else {
        set params {}
    }

    if {$sign} {
        lappend params --sign
        array set tmp {}
        foreach key [Get $token -property signers] {
            array unset tmp
            array set tmp [InfoKey $token -key $key]
            lappend params -u $tmp(keyid)
        }
    }

    if {[::info exists recipients]} {
        lappend params --encrypt

        if {!$sign} {
            lappend params --batch
        }

        foreach name [$recipients -operation list] {
            lappend params -r $name
        }

        if {[$recipients -operation count] == 0} {
            return -code error "No recipents in token"
        }
    } else {
        lappend params --symmetric
    }

    return [eval [list ExecGPG $token encrypt $input \
                               --no-tty \
                               --status-fd 2 \
                               --logger-fd 2 \
                               --command-fd 0 \
                               --no-verbose \
                               --output -] \
                               $params \
                               --]
}

proc ::gpg::StartKey {token args} {
    variable $token
    upvar 0 $token state

    if {[::info exists state(keyidx)]} {
        return -code error \
               "already doing a key listing, end that one first"
    }

    set patterns {}
    set operation --list-keys

    foreach {key val} $args {
        switch -- $key {
            -patterns {
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

    set state(keylist) [ListKeys $token $operation $patterns]
    set state(keyidx) -1

    return
}

proc ::gpg::ListKeys {token operation patterns} {
    variable $token
    upvar 0 $token state

    set gpgOutput [eval [list ExecGPG $token list-keys "" \
                              --batch \
                              --no-tty \
                              --status-fd 2 \
                              --with-colons \
                              --fixed-list-mode \
                              --with-fingerprint \
                              --with-fingerprint \
                              $operation --] $patterns]

    return [Parse $token $gpgOutput]
}

proc ::gpg::NextKey {token args} {
    variable $token
    upvar 0 $token state

    if {![::info exists state(keyidx)]} {
        return -code error "not doing a key listing"
    }

    return [lindex $state(keylist) [incr state(keyidx)]]
}

proc ::gpg::DoneKey {token args} {
    variable $token
    upvar 0 $token state

    if {![::info exists state(keyidx)]} {
        return -code error "not doing a key listing"
    }

    unset state(keylist)
    unset state(keyidx)
    return
}

proc ::gpg::InfoKey {token args} {
    variable keys
    variable $token
    upvar 0 $token state

    foreach {key val} $args {
        switch -- $key {
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

    if {[::info exists keys($fingerprint)]} {
        return $keys($fingerprint)
    } else {
        return -code error "Invalid Value"
    }
}

proc ::gpg::Parse {token gpgOutput} {
    variable keys
    variable $token
    upvar 0 $token state

    set res {}
    set key {}
    set st ""
    foreach line [split $gpgOutput "\n"] {
        set fields [split $line ":"]
        switch -- [lindex $fields 0] {
            pub -
            sec -
            crt -
            crs {
                # Store the current key and start a new one
                set st key
                array set tmp $key
                if {[::info exists tmp(fingerprint)]} {
                    set keys($tmp(fingerprint)) $key
                    lappend res $tmp(fingerprint)
                }
                array unset tmp
                set key {}
            }
            sub -
            ssb {
                # Start a new subkey
                set st subkey
            }
            sig {
                # Signature
            }
        }
        set key [concat $key [ParseRecord $st $fields]]
    }

    # Store the last key
    array set tmp $key
    if {[::info exists tmp(fingerprint)]} {
        set keys($tmp(fingerprint)) $key
        lappend res $tmp(fingerprint)
    }

    return $res
}

proc ::gpg::ParseRecord {state fields} {
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
            switch -- $state {
                key {
                    set fingerprint [lindex $fields 9]
                    return [list fingerprint $fingerprint]
                }
                subkey {
                    # TODO
                    return {}
                }
            }
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

# TODO: Asynchronous processing (non-blocking channel)

proc ::gpg::ExecGPG {token operation input args} {
    variable gpgExecutable
    variable keys

    Debug 1 $args

    # Raise an error if there are dangerous arguments

    foreach arg $args {
        if {[string first < $arg] == 0 || [string first > $arg] == 0 || \
            [string first 2> $arg] == 0 || [string first | $arg] == 0 || \
            [string equal & $arg]} {

            return -code error \
                   [format "forbidden argument \"%s\" in exec call" $arg]
        }
    }

    if {[string equal $operation list-keys]} {
        set fd [open |[linsert $args 0 $gpgExecutable] r]
        fconfigure $fd -translation binary
        set data [read $fd]
        Debug 2 $data
        catch {close $fd}
        return $data
    }

    # Using either [chan pipe] from Tcl 8.6 or [pipe] from TclX.
    # It's the only way of 'half-closing' a channel.

    if {[catch {chan pipe} pList]} {
        set pList [pipe]
    }
    foreach {pRead pWrite} $pList break
    fconfigure $pRead -translation binary

    if {[catch {chan pipe} qList]} {
        set qList [pipe]
    }
    foreach {qRead qWrite} $qList break
    fconfigure $qRead -translation binary

    # Redirect stdout and stderr to pipes

    lappend args >@ $pWrite 2>@ $qWrite

    set fd [open |[linsert $args 0 $gpgExecutable] w]
    fconfigure $fd -translation binary -buffering none
    close $pWrite
    close $qWrite

    switch -- $operation {
        encrypt -
        decrypt -
        sign {
            while {[gets $qRead line] >= 0} {
                Debug 2 $line
                set fields [split $line]

                if {![string equal [lindex $fields 0] "\[GNUPG:\]"]} continue

                switch -- [lindex $fields 1] {
                    BEGIN_ENCRYPTION { break }
                    BEGIN_SIGNING { break }
                    USERID_HINT {
                        set userid_hint [join [lrange $fields 2 end]]
                    }
                    NEED_PASSPHRASE {
                        if {![::info exists hint]} {
                            set hint ENTER
                        } else {
                            set hint TRY_AGAIN
                        }
                        set pcb [Get $token -property passphrase-callback]
                        if {[string equal $pcb ""]} {
                            return -code error "No passphrase"
                        }
                        set desc \
                            [join [list $hint $userid_hint \
                                        [join [lrange $fields 2 end] " "]] \
                                  "\n"]
                        Debug 2 $desc
                        puts $fd [eval $pcb [list [list token $token \
                                                        description $desc]]]
                    }
                    KEYEXPIRED {
                        return -code error "Key expired"
                    }
                    NEED_PASSPHRASE_SYM {
                        set pcb [Get $token -property passphrase-callback]
                        if {[string equal $pcb ""]} {
                            return -code error "No passphrase"
                        }
                        puts $fd [eval $pcb [list [list token $token \
                                                        description ENTER]]]
                    }
                }
            }

            if {![string equal $input ""]} {
                puts $fd $input
            }
            catch {close $fd}

            set data [read $pRead]
        }
        verify -
        dverify {
            # Here $input contains either a signature, or a signed material
            # if a signature is detached.
            puts -nonewline $fd $input
            catch {close $fd}

            array unset sig
            array set sig [list status nosig validity unknown summary {}]

            set signatures {}

            while {[gets $qRead line] >= 0} {
                Debug 2 $line
                set fields [split $line]

                if {![string equal [lindex $fields 0] "\[GNUPG:\]"]} continue

                switch -- [lindex $fields 1] {
                    NEWSIG {}
                    GOODSIG {
                        set sig(status) good
                        set sig(keyid) [lindex $fields 2]
                        set sig(uid) [join [lrange $fields 3 end]]
                    }
                    EXPSIG {
                        set sig(status) expired
                        set sig(keyid) [lindex $fields 2]
                        set sig(uid) [join [lrange $fields 3 end]]
                    }
                    EXPKEYSIG {
                        set sig(status) expiredkey
                        set sig(keyid) [lindex $fields 2]
                        set sig(uid) [join [lrange $fields 3 end]]
                    }
                    REVKEYSIG {
                        set sig(status) revokedkey
                        set sig(keyid) [lindex $fields 2]
                        set sig(uid) [join [lrange $fields 3 end]]
                    }
                    BADSIG {
                        set sig(status) bad
                        lappend sig(summary) red
                        set sig(keyid) [lindex $fields 2]
                        set sig(uid) [join [lrange $fields 3 end]]
                    }
                    ERRSIG {
                        switch -- [lindex $fields 7] {
                            9 {
                                set sig(status) nokey
                            }
                            default {
                                set sig(status) error
                            }
                        }
                        set sig(keyid) [lindex $fields 2]
                    }
                    VALIDSIG {
                        set sig(fingerprint) [lindex $fields 2]
                        set sig(created) [lindex $fields 4]
                        if {[lindex $fields 5] != 0} {
                            set sig(expires) [lindex $fields 5]
                        }
                        set sig(key) [lindex $fields 11]
                        if {![::info exists keys($sig(key))]} {
                            ListKeys $token --list-keys $sig(key)
                        }
                    }
                    SIG_ID {}
                    NODATA -
                    UNEXPECTED {
                        set sig(status) nosig
                        lappend signatures [array get sig]
                        array unset sig
                        array set sig [list status nosig validity unknown \
                                            summary {}]
                    }
                    KEYEXPIRED {
                        set sig(status) expiredkey
                    }
                    KEYREVOKED {
                        set sig(status) revokedkey
                    }
                    TRUST_UNDEFINED {
                        set sig(validity) unknown
                    }
                    TRUST_NEVER {
                        set sig(validity) never
                        switch -- $sig(status) {
                            good -
                            expired -
                            expiredkey {
                                lappend sig(summary) red
                            }
                        }
                    }
                    TRUST_MARGINAL {
                        set sig(validity) marginal
                    }
                    TRUST_FULLY -
                    TRUST_ULTIMATE {
                        set sig(validity) full
                        switch -- $sig(status) {
                            good -
                            expired -
                            expiredkey {
                                lappend sig(summary) green
                            }
                        }
                    }
                }

                switch -- [lindex $fields 1] {
                    BADSIG -
                    ERRSIG -
                    TRUST_UNDEFINED -
                    TRUST_NEVER -
                    TRUST_MARGINAL -
                    TRUST_FULLY -
                    TRUST_ULTIMATE {
                        # Finish a signature
                        if {[string equal $sig(status) good] && \
                                [llength $sig(summary)] == 1 && \
                                [string equal [lindex $sig(summary) 0] green]} {
                            lappend sig(summary) valid
                        }
                        lappend signatures [array get sig]
                        array unset sig
                        array set sig [list status nosig validity unknown \
                                            summary {}]
                    }
                }
            }

            set statuses {}
            foreach s $signatures {
                array unset sig
                array set sig $s
                lappend statuses $sig(status)
            }
            set statuses [lsort -unique $statuses]
            switch -- [llength $statuses] {
                0 {
                    set status nosig
                }
                1 {
                    # All signatures have the same status
                    set status [lindex $statuses 0]
                }
                default {
                    # There are different statuses
                    set ststus diff
                }
            }

            if {[string equal $operation verify] && \
                    ![string equal $status nosig]} {

                # "verify" means non-detached signature, so gpg reports the
                # signed message to stdout.

                set plaintext [read $pRead]
                set data [list plaintext $plaintext]
            } else {
                set data {}
            }

            lappend data status $status signatures $signatures
        }
    }

    # If gpg returns nonzero status or writes to stderr, close raises
    # an error. So, the catch is necessary.
    # TODO: Process the error

    catch {close $qRead}
    catch {close $pRead}
    return $data
}

# ::gpg::recipient --
#
#       Create a new GPG recipient token.
#
# Arguments:
#       None.
#
# Result:
#       A recipient token (which is used as a procedure).
#
# Side effects:
#       A new procedure and a state variable are created. Also deleting of
#       the procedure is traced to unset the state variable.

proc ::gpg::recipient {} {
    variable rid

    if {![::info exists rid]} {
        set rid 0
    }

    set token [namespace current]::recipient[incr rid]
    variable $token
    upvar 0 $token state

    set state(recipients) {}

    proc $token {args} "eval {[namespace current]::RecipientExec} {$token} \$args"

    trace add command $token delete [namespace code [list RecipientFree $token]]

    return $token
}

# ::gpg::RecipientFree --
#
#       Unset state variable corresponding to a recipient token.
#
# Arguments:
#       token       A recipient context token created in ::gpg::recipient.
#       args        (unused) Arguments added by trace.
#
# Result
#       An empty string.
#
# Side effects:
#       A state variable is destroyed.

proc ::gpg::RecipientFree {token args} {
    variable $token
    upvar 0 $token state

    catch {unset state}
    return
}

# ::gpg::RecipientExec --
#
#       Execute a recipient operation. This procedure is invoked when a user
#       calls [$token -operation ...] for a recipient token.
#
# Arguments:
#       token       A recipient token created in ::gpg::recipient.
#       args        Arguments serialized array. It must contain pair
#                   -operation <op>. The other arguments are operation-
#                   dependent.
#
# Result:
#       The result of a corresponding operation.
#
# Side effects:
#       The side effects of a corresponding operation.

proc ::gpg::RecipientExec {token args} {
    set newArgs {}
    foreach {key val} $args {
        switch -- $key {
            -operation { set op $val }
            default { lappend newArgs $key $val }
        }
    }

    if {![::info exists op]} {
        return -code error "Missing operation"
    }

    switch -- $op {
        info  { return {info add count list} }
        add   { return [eval [list RecipientAdd   $token] $newArgs] }
        count { return [eval [list RecipientCount $token] $newArgs] }
        list  { return [eval [list RecipientList  $token] $newArgs] }
        default {
            return -code error [format "Illegal operation \"%s\"" $op]
        }
    }
}

# ::gpg::RecipientAdd --
#
#       Add a recipient to a recipient token.
#
# Arguments:
#       token           A recipient token created by ::gpg::recipient.
#       -name name      A recipient name.
#       -validity val   (optional, defaults to unknown) A minimum acceptable
#                       validity.
#
# Result:
#       Empty string.
#
# Side effects:
#       A pair {name val} is added to a recipient list.

proc ::gpg::RecipientAdd {token args} {
    variable validities
    variable $token
    upvar 0 $token state

    set validity unknown
    foreach {key val} $args {
        switch -- $key {
            -name { set name $val }
            -validity {
                set validity $val
            }
        }
    }

    if {![::info exists name]} {
        return -code error "-name switch must be provided"
    }

    if {[lsearch -exact $validities $validity] < 0} {
        return -code error \
               [format "bad validity \"%s\": must be %s" \
                       $val [JoinOptions $validities]]
    }

    lappend state(recipients) [list $name $validity]
    return
}

# ::gpg::RecipentCount --
#
#       Return recipients count for recipient token.
#
# Arguments:
#       token           A recipient token created by ::gpg::recipient.
#
# Result:
#       A number of added recipients.
#
# Side effects:
#       None.

proc ::gpg::RecipientCount {token} {
    variable $token
    upvar 0 $token state

    return [llength $state(recipients)]
}

# ::gpg::RecipentCount --
#
#       Return list of recipient names for recipient token.
#
# Arguments:
#       token           A recipient token created by ::gpg::recipient.
#
# Result:
#       A list of added recipient names.
#
# Side effects:
#       None.

proc ::gpg::RecipientList {token} {
    variable $token
    upvar 0 $token state

    set recs {}
    foreach r $state(recipients) {
        lappend recs [lindex $r 0]
    }
    return $recs
}

# ::gpg::JoinOptions --
#
#       A helper procedure which formats supplied options to show them to a
#       user. For example {op1 op2 op3} is formatted to "op1, op2, or op3".
#       It is useful for error messages.
#
# Arguments:
#       optList         Options list.
#
# Result:
#       Formatted string.
#
# Side effects:
#       None.

proc ::gpg::JoinOptions {optList} {
    switch -- [llength $optList] {
        0 - 1 {
            return [lindex $optList 0]
        }
        default {
            return "[join [lrange $optList 0 end-1] {, }], or\
                    [lindex $optList end]"
        }
    }
}


proc ::gpg::TempFile {} {
    # Code is borrowed from http://wiki.tcl.tk/772
    switch $::tcl_platform(platform) {
        unix {
            set tmpdir /tmp
        } macintosh {
            set tmpdir $::env(TRASH_FOLDER)
        } default {
            set tmpdir [pwd]
            catch {set tmpdir $::env(TMP)}
            catch {set tmpdir $::env(TEMP)}
        }
    }

    if {![file writable $tmpdir]} {
        return -code error \
               [format "temporary directory \"%s\" is not writable" $tmpdir]
    }

    set chars "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    set nrand_chars 10
    set maxtries 10
    set access [list RDWR CREAT EXCL TRUNC]
    set permission 0600
    set fd ""
    set mypid [pid]

    for {set i 0} {$i < $maxtries} {incr i} {
        set newname ""
        for {set j 0} {$j < $nrand_chars} {incr j} {
            append newname \
                   [string index $chars \
                           [expr {([clock clicks] ^ $mypid) % 62}]]
        }
        set newname [file join $tmpdir $newname]

        if {![file exists $newname]} {
            if {![catch {open $newname $access $permission} fd]} {
                fconfigure $fd -translation binary
                return [list $newname $fd]
            }
        }
    }
    if {[string equal $fd ""]} {
        return -code error \
               "failed to find an unused temporary file name"
    } else {
        return -code error \
               [format "failed to open a temporary file: %s" $fd]
    }
}

# ::gpg::Debug --
#
#       Prints debug information.
#
# Arguments:
#       level   A debug level.
#       msg     A debug message.
#
# Result:
#       An empty string.
#
# Side effects:
#       A debug message is printed to the console if the value of
#       ::gpg::debug variable is not less than num.

proc ::gpg::Debug {level msg} {
    variable debug

    if {$debug >= $level} {
        puts "[lindex [::info level -1] 0]: $msg"
    }

    return
}

# vim:ts=8:sw=4:sts=4:et
