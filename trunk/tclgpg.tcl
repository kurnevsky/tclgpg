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
                                 expired expiredkey]
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
        info      { return [eval [list Info     $token] $newArgs] }
        cancel    { return [eval [list Cancel   $token] $newArgs] }
        wait      { return [eval [list Wait     $token] $newArgs] }
        get       { return [eval [list Get      $token] $newArgs] }
        set       { return [eval [list Set      $token] $newArgs] }
        start-key { return [eval [list StartKey $token] $newArgs] }
        next-key  { return [eval [list NextKey  $token] $newArgs] }
        done-key  { return [eval [list DoneKey  $token] $newArgs] }
        info-key  { return [eval [list InfoKey  $token] $newArgs] }
        encrypt   { return [eval [list Encrypt  $token] $newArgs] }
        sign      { return [eval [list Sign     $token] $newArgs] }
        verify    { return [eval [list Verify   $token] $newArgs] }
        decrypt   { return [eval [list Decrypt  $token] $newArgs] }
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
        # A signature is detached, so create a temporary file
        # with a signature.
        set params {--enable-special-filenames}

        set name_fd [TempFile]
        foreach {filename fd} $name_fd break

        puts $fd $signature
        close $fd

        set fnames [list $filename -]
    } else {
        set params {}
        set fnames {}
        set input $signature
    }

    set res [eval [list ExecGPG $token verify $input \
                                --no-tty \
                                --status-fd 2 \
                                --logger-fd 2 \
                                --command-fd 0 \
                                --no-verbose \
                                --output - \
                                --verify] \
                                $params \
                                -- $fnames]
    if {[::info exists filename]} {
        file delete -force -- $filename
    }
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

    if {[Get $token -property armor]} {
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

    if {[Get $token -property armor]} {
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
    } else {
        lappend params --batch
    }

    foreach name [$recipients -operation list] {
        lappend params -r $name
    }

    return [eval [list ExecGPG $token encrypt $input \
                               --no-tty \
                               --status-fd 2 \
                               --logger-fd 2 \
                               --command-fd 0 \
                               --no-verbose \
                               --encrypt \
                               --output -] \
                               $params \
                               --]
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

    set keystoken [namespace current]::keys$state(id)
    variable $keystoken
    upvar 0 $keystoken keys

    catch {unset keys}
    array set keys {}

    set state(keystoken) $keystoken

    set gpgOutput [eval [list ExecGPG $token list-keys "" \
                           --batch \
                           --no-tty \
                           --status-fd 2 \
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

# TODO: Asynchronous processing (non-blocking channel)

proc ::gpg::ExecGPG {token operation input args} {
    variable gpgExecutable

    puts $args

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
        set data [read $fd]
        puts $data
        catch {close $fd}
        return $data
    }

    # Using either [chan pipe] from Tcl 8.6 or [pipe] from TclX.
    # It's the only way of 'half-closing' a channel.

    if {[catch {chan pipe} pList]} {
        set pList [pipe]
    }
    foreach {pRead pWrite} $pList break

    if {[catch {chan pipe} qList]} {
        set qList [pipe]
    }
    foreach {qRead qWrite} $qList break
    #fconfigure $qRead -blocking 0 -buffering none

    # Redirect stdout and stderr to pipes

    lappend args >@ $pWrite 2>@ $qWrite

    set fd [open |[linsert $args 0 $gpgExecutable] w]
    fconfigure $fd -buffering none
    close $pWrite
    close $qWrite

    switch -- $operation {
        encrypt -
        decrypt -
        sign {
            while {[gets $qRead line] >= 0} {
                puts $line
                set fields [split $line]

                if {![string equal [lindex $fields 0] "\[GNUPG:\]"]} continue

                switch -- [lindex $fields 1] {
                    BEGIN_ENCRYPTION { break }
                    BEGIN_SIGNING { break }
                    USERID_HINT {
                        # TODO
                    }
                    NEED_PASSPHRASE {
                        puts $fd [eval [Get $token -property passphrase-callback] \
                                       [lrange $fields 2 end]]
                    }
                }
            }

            if {![string equal $input ""]} {
                puts $fd $input
            }
            catch {close $fd}

            set data [read $pRead]
        }
        verify {
            puts $fd $input
            catch {close $fd}

            while {[gets $qRead line] >= 0} {
                puts $line
                set fields [split $line]

                if {![string equal [lindex $fields 0] "\[GNUPG:\]"]} continue

                switch -- [lindex $fields 1] {
                    #TODO {}
                }
            }

            set data "" ; #TODO
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


proc TempFile {} {
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

# vim:ts=8:sw=4:sts=4:et
