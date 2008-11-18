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

if {[catch {load [file join [file dirname [info script]] \
			    tclgpg[info sharedlibextension]]} res]} {
    if {[package vsatisfies $::tcl_version 8.6]} {
	interp alias {} pipe {} chan pipe
    } elseif {[catch {package require pipe}]} {
	package require Tclx
    }
}

if {[llength [auto_execok gpg]] == 0 || \
        ![regexp {^gpg \(GnuPG\) ([\d\.]+)} \
                 [exec [lindex [auto_execok gpg] 0] --version] \
                 -> gpgVersion]} {
    return -code error "GnuPG binary is unusable"
}

if {[package vsatisfies $gpgVersion 2.0] && \
        ![info exists ::env(GPG_AGENT_INFO)]} {
    unset gpgVersion
    return -code error \
           "GnuPG 2 cannot be used without gpg-agent"
}

package provide gpg 1.0

namespace eval ::gpg {
    variable validities [list unknown undefined never marginal full ultimate]

    variable Version $::gpgVersion
    unset gpgVersion

    # Variable to store public keys
    variable keys

    variable debug 0
}

# ::gpg::executable --
# Purpose:
#  Finds a GnuPG executable in the system using the same rules [exec] does.
# Returns:
#  Full pathname of the first occurence of the GnuPG executable found
#  or an empty string if the search yielded no results.
# Side effects:
#  Updates the global Tcl array auto_execs on success (see library(3tcl)).
proc ::gpg::executable {} {
    lindex [auto_execok gpg] 0
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

    # Default settings
    set state(armor) false
    set state(textmode) false

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
            default    { lappend newArgs $key $val }
        }
    }

    if {![::info exists op]} {
        return -code error "missing operation"
    }

    switch -- $op {
        cancel    { set res [eval [list Cancel   $token] $newArgs] }
        wait      { set res [eval [list Wait     $token] $newArgs] }
        get       { set res [eval [list Get      $token] $newArgs] }
        set       { set res [eval [list Set      $token] $newArgs] }
        list-keys { set res [eval [list ListKeys $token] $newArgs] }
        start-key { set res [eval [list StartKey $token] $newArgs] }
        next-key  { set res [eval [list NextKey  $token] $newArgs] }
        done-key  { set res [eval [list DoneKey  $token] $newArgs] }
        info-key  { set res [eval [list InfoKey  $token] $newArgs] }
        encrypt   { set res [eval [list Encrypt  $token] $newArgs] }
        sign      { set res [eval [list Sign     $token] $newArgs] }
        verify    { set res [eval [list Verify   $token] $newArgs] }
        decrypt   { set res [eval [list Decrypt  $token] $newArgs] }
        default   {
            return -code error \
                   [format "unknown operation \"%s\":\
                            must be %s" $op [JoinOptions {cancel wait get set
                                                          encrypt decrypt sign
                                                          verify start-key
                                                          next-key done-key
                                                          info-key}]]
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

# ::gpg::Set --
#
#       Set a given GPG context property to a given value.
#
# Arguments:
#       token           A GPG context token created in ::gpg::context.
#       -property prop  A property name.
#       -value value    (optional) A value to set. If missing then property
#                       is set to an empty string which essentially means it's
#                       unset.
#
# Result:
#       Empty string in case of success, or an error if a property is missing
#       or unknown.
#
# Side effects:
#       A state variable corresponding to a given property is set.

proc ::gpg::Set {token args} {
    variable properties
    variable $token
    upvar 0 $token state

    Debug 2 "$token $args"

    set value ""
    foreach {key val} $args {
        switch -- $key {
            -property { set prop  $val }
            -value    { set value $val }
            default   {
                return -code error \
                       [format "unknown option \"%s\":\
                                must be %s" $op [JoinOptions {-operation
                                                              -property
                                                              -value}]]
            }
        }
    }

    variable properties [list protocol armor textmode number-of-certs \
                              keylistmode passphrase-callback \
                              progress-callback idle-callback signers]

    if {![::info exists prop]} {
        return -code error \
               [format "missing property:\
                        must be %s" $prop [JoinOptions $properties]]
    } elseif {[lsearch -exact $properties $prop] >= 0} {
        switch -- $prop {
            armor -
            textmode {
                if {[string is boolean -strict $value]} {
                    set state($prop) $value
                } else {
                    return -code error \
                           [format "invalid %s value \"%s\":\
                                    must be boolean" $prop $value]
                }
            }
            default {
                # TODO: Checking other properties values
                set state($prop) $value
            }
        }
        return
    } else {
        return -code error \
               [format "unknown property \"%s\":\
                        must be %s" $prop [JoinOptions $properties]]
    }
}

# ::gpg::Get --
#
#       Return the value of a given GPG context property.
#
# Arguments:
#       token           A GPG context token created in ::gpg::context.
#       -property prop  A property name.
#
# Result:
#       A given property value if it's set, or empty string if it's unset
#       in case of success, or an error if a property is missing
#       or unknown.
#
# Side effects:
#       None.

proc ::gpg::Get {token args} {
    variable $token
    upvar 0 $token state

    Debug 2 "$token $args"

    foreach {key val} $args {
        switch -- $key {
            -property { set prop $val }
            default   {
                return -code error \
                       [format "unknown option \"%s\":\
                                must be %s" $op [JoinOptions {-operation
                                                              -property}]]
            }
        }
    }

    set properties [list protocol armor textmode number-of-certs \
                         keylistmode passphrase-callback \
                         progress-callback idle-callback signers \
                         last-op-info]

    if {![::info exists prop]} {
        return -code error \
               [format "missing property:\
                        must be %s" $prop [JoinOptions $properties]]
    } elseif {[lsearch -exact $properties $prop] >= 0} {
        if {[::info exists state($prop)]} {
            return $state($prop)
        } else {
            return ""
        }
    } else {
        return -code error \
               [format "unknown property \"%s\":\
                        must be %s" $prop [JoinOptions $properties]]
    }
}

# ::gpg::Sign --
#
#       Sign message.
#
# Arguments:
#       token           A GPG context token created in ::gpg::context.
#       -input input    A message to sign.
#       -mode mode      (optional, defaults to normal) A signing mode. May be
#                       normal, detach, clear.
#
# Result:
#       A signed message.
#
# Side effects:
#       None.

proc ::gpg::Sign {token args} {
    variable $token
    upvar 0 $token state

    set mode normal
    foreach {key val} $args {
        switch -- $key {
            -input  { set input $val }
            -mode   { set mode  $val }
            default {
                return -code error \
                       [format "unknown option \"%s\":\
                                must be %s" $op [JoinOptions {-operation
                                                              -input
                                                              -mode}]]
            }
        }
    }

    if {![::info exists input]} {
        return -code error "missing input to sign"
    }

    if {[Get $token -property armor]} {
        set params {--armor}
    } else {
        set params {--no-armor}
    }

    switch -- $mode {
        normal  { lappend params --sign }
        detach  { lappend params --detach-sign }
        clear   { lappend params --clearsign }
        default {
            return -code error \
                   [format "unknown mode \"%s\":\
                            must be %s" $mode [JoinOptions {normal
                                                            detach
                                                            clear}]]
        }
    }

    array set tmp {}
    foreach key [Get $token -property signers] {
        array unset tmp
        array set tmp [InfoKey $token -key $key]
        lappend params -u $tmp(keyid)
    }

    set gpgChannels [eval ExecGPG $token $params --]
    return [UseGPG $token sign $gpgChannels $input]
}

# ::gpg::Encrypt --
#
#       Encrypt message.
#
# Arguments:
#       token           A GPG context token created in ::gpg::context.
#       -input input    A message to encrypt.
#       -recipients rec (optional) Recipients token. If present then the
#                       message will be encrypted using asymmetric algorithm
#                       using keys of recipients added to the token. If
#                       missing then the message will be encrypted using
#                       symmetric cipher.
#       -sign bool      (optional, defaults to false) A boolean variable which
#                       specifies whether also to sign the message.
#
# Result:
#       An encrypted and optionally signed message.
#
# Side effects:
#       None.

proc ::gpg::Encrypt {token args} {
    variable $token
    upvar 0 $token state

    set sign false
    foreach {key val} $args {
        switch -- $key {
            -input      { set input $val }
            -recipients {
                if {[catch {RecipientCount $val}]} {
                    return -code error \
                           [format "invalid recipients token \"%s\" $val"]
                }
                set recipients $val
            }
            -sign       {
                if {![string is boolean -strict $val]} {
                    return -code error \
                           [format "invalid -sign value \"%s\": must be boolean"]
                }
                set sign $val
            }
            default {
                return -code error \
                       [format "unknown option \"%s\":\
                                must be %s" $op [JoinOptions {-operation
                                                              -input
                                                              -recipients
                                                              -sign}]]
            }
        }
    }

    if {![::info exists input]} {
        return -code error "missing input to encrypt"
    }

    if {[Get $token -property armor]} {
        set params {--armor}
    } else {
        set params {--no-armor}
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
        if {[RecipientCount $recipients] == 0} {
            return -code error "no recipents in token"
        }

        lappend params --encrypt

        if {!$sign} {
            lappend params --batch
        }

        set trust {--trust-model always}
        foreach name_trust [RecipientFullList $recipients] {
            switch -- [lindex $name_trust 1] {
                ultimate -
                full {}
                default {
                    set trust {}
                }
            }
        }

        set params [concat $params $trust]

        foreach name [RecipientList $recipients] {
            lappend params -r $name
        }
    } else {
        lappend params --symmetric
    }

    set gpgChannels [eval ExecGPG $token $params --]
    return [UseGPG $token encrypt $gpgChannels $input]
}

# ::gpg::Verify --
#
#       Verify message signature.
#
# Arguments:
#       token           A GPG context token created in ::gpg::context.
#       -signature sig  A GPG signature.
#       -input input    (optional) A message to verify if a signature is
#                       detached.
#
# Result:
#       A serialised array with signature status and a list of all signature
#       properties. If a signature isn't detached this array contains also
#       a signed text.
#
# Side effects:
#       None.

proc ::gpg::Verify {token args} {
    variable $token
    upvar 0 $token state

    foreach {key val} $args {
        switch -- $key {
            -signature { set signature $val }
            -input     { set input     $val }
            default    {
                return -code error \
                       [format "unknown option \"%s\":\
                                must be %s" $op [JoinOptions {-operation
                                                              -signature
                                                              -input}]]
            }
        }
    }

    if {![::info exists signature]} {
        return -code error "missing signature to verify"
    }

    if {[::info exists input]} {
        set gpgChannels [ExecGPG $token --enable-special-filenames \
                                 --verify \
                                 -- $signature]
        set res [UseGPG $token verify $gpgChannels $input]
    } else {
        set gpgChannels [ExecGPG $token --]
        set res [UseGPG $token "" $gpgChannels $signature]
    }

    Debug 2 $res
    return $res
}

# ::gpg::Decrypt --
#
#       Decrypt GPG encrypted message and optionally verify its signature.
#
# Arguments:
#       token               A GPG context token created in ::gpg::context.
#       -input input        A message to decrypt.
#       -checkstatus bool   (optional, defaults to false) Whether to verify
#                           message signature.
#
# Result:
#       A serialised array with decrypted message and if signature
#       verification was requested then the array contains also signature
#       status and a list of all signature properties.
#
# Side effects:
#       None.

proc ::gpg::Decrypt {token args} {
    variable $token
    upvar 0 $token state

    set checkstatus false
    foreach {key val} $args {
        switch -- $key {
            -input       { set input $val }
            -checkstatus {
                if {![string is boolean -strict $val]} {
                    return -code error \
                           [format "invalid -checkstatus value \"%s\":\
                                    must be boolean"]
                }
                set checkstatus $val
            }
            default    {
                return -code error \
                       [format "unknown option \"%s\":\
                                must be %s" $op [JoinOptions {-operation
                                                              -input
                                                              -checkstatus}]]
            }
        }
    }

    if {![::info exists input]} {
        return -code error "missing input to decrypt"
    }

    set gpgChannels [ExecGPG $token --decrypt -- $input]
    set res [UseGPG $token decrypt $gpgChannels]

    # UseGPG returns decrypted message and signature status, so filter out
    # unnecessary info

    if {!$checkstatus} {
        foreach {key val} $res {
            switch -- $key {
                plaintext {
                    return [list $key $val]
                }
            }
        }
    }

    return $res
}

# ::gpg::ListKeys --
#
#       Return a key list.
#
# Arguments:
#       token               A GPG context token created in ::gpg::context.
#       -patterns patterns  A list of patterns to search for in keys available
#                           to GnuPG. Patterns may contain key ID, fingerprint,
#                           user ID etc. See gpg(1) manual page for details.
#       -secretonly bool    (optional, defaults to false) A boolean which shows
#                           if secret keys should be found. If false then only
#                           public keys are searched.
#
# Result:
#       A list of matching keys.
#
# Side effects:
#       A global keys array is populated by keys which match given patterns.

proc ::gpg::ListKeys {token args} {
    variable $token
    upvar 0 $token state

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
                           [format "invalid -secretonly value \"%s\":\
                                    must be boolean" $val]
                }
            }
            default {
                return -code error \
                       [format "unknown option \"%s\":\
                                must be %s" $key [JoinOptions {-operation
                                                               -patterns
                                                               -secretonly}]]
            }
        }
    }

    return [FindKeys $token $operation $patterns]
}

# ::gpg::StartKey --
#
#       Start an element-by-element traversing through a key list.
#
# Arguments:
#       token               A GPG context token created in ::gpg::context.
#       -patterns patterns  A list of patterns to search for in keys available
#                           to GnuPG. Patterns may contain key ID, fingerprint,
#                           user ID etc. See gpg(1) manual page for details.
#       -secretonly bool    (optional, defaults to false) A boolean which shows
#                           if secret keys should be found. If false then only
#                           public keys are searched.
#
# Result:
#       Empty string or error if a search is already started earlier.
#
# Side effects:
#       A global keys array is populated by keys which match given patterns.
#       Also, NextKey becomes usable.

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
                           [format "invalid -secretonly value \"%s\":\
                                    must be boolean" $val]
                }
            }
            default {
                return -code error \
                       [format "unknown option \"%s\":\
                                must be %s" $key [JoinOptions {-operation
                                                               -patterns
                                                               -secretonly}]]
            }
        }
    }

    set state(keylist) [FindKeys $token $operation $patterns]
    set state(keyidx) -1

    return
}

# ::gpg::NextKey --
#
#       Return the next element in a key search started by StartKey.
#
# Arguments:
#       token               A GPG context token created in ::gpg::context.
#
# Result:
#       A key fingerprint or empty string if a list is ended. Error is
#       returned if a search wasn't started yet.
#
# Side effects:
#       None.

proc ::gpg::NextKey {token} {
    variable $token
    upvar 0 $token state

    if {![::info exists state(keyidx)]} {
        return -code error "not doing a key listing"
    }

    return [lindex $state(keylist) [incr state(keyidx)]]
}

# ::gpg::DoneKey --
#
#       Finish a key search started by StartKey.
#
# Arguments:
#       token               A GPG context token created in ::gpg::context.
#
# Result:
#       Empty string or error if a search isn't started yet.
#
# Side effects:
#       Search is finished, so NextKey will return error.

proc ::gpg::DoneKey {token} {
    variable $token
    upvar 0 $token state

    if {![::info exists state(keyidx)]} {
        return -code error "not doing a key listing"
    }

    unset state(keylist)
    unset state(keyidx)
    return
}

# ::gpg::InfoKey --
#
#       Return key info.
#
# Arguments:
#       token           A GPG context token created in ::gpg::context.
#       -key keytoken   A key fingerprint which is used as a key token.
#
# Result:
#       A serialised array with key info (some array indices may repeat,
#       so don't really use it as an array) or error if this key wasn't
#       listed using FindKeys yet..
#
# Side effects:
#       None.

proc ::gpg::InfoKey {token args} {
    variable keys

    foreach {key val} $args {
        switch -- $key {
            -key {
                set fingerprint $val
            }
            default {
                return -code error \
                    [format "unknown option \"%s\":\
                             must be %s" $key [JoinOptions {-operation
                                                            -key}]]
            }
        }
    }

    if {![::info exists fingerprint]} {
        return -code error "missing key"
    }

    if {[::info exists keys($fingerprint)]} {
        return $keys($fingerprint)
    } else {
        return -code error "invalid key"
    }
}

# ::gpg::FindKeys --
#
#       A helper procedure which requests gpg for a list of keys and returns
#       their fingerprints (which are used as indices of a global keys array)
#       list.
#
# Arguments:
#       token               A GPG context token created in ::gpg::context.
#       operation           --list-keys for public keys list or
#                           --list-secret-keys for secret keys list.
#       patterns            A list of patterns to search for in keys available
#                           to GnuPG. Patterns may contain key ID, fingerprint,
#                           user ID etc. See gpg(1) manual page for details.
#
# Result:
#       A list of keys which match given patterns.
#
# Side effects:
#       A global keys array is populated by keys which match given patterns.

proc ::gpg::FindKeys {token operation patterns} {

    set channels [eval ExecGPG $token --batch \
                                      --with-colons \
                                      --fixed-list-mode \
                                      --with-fingerprint \
                                      --with-fingerprint \
                                      $operation -- $patterns]

    foreach {filename stdin_fd stdout_fd stderr_fd status_fd} $channels break
    # TODO: Do we have to set encoding to UTF-8?
    set res [Parse [read $stdout_fd]]
    catch {close $stdin_fd}
    catch {close $stdout_fd}
    catch {close $stderr_fd}
    catch {close $status_fd}
    return $res
}

proc ::gpg::Parse {gpgOutput} {
    variable keys

    set res {}
    set key {}
    set subkey {}
    set subkeys {}
    set st ""
    foreach line [split $gpgOutput "\n"] {
        set fields [split $line ":"]
        switch -- [lindex $fields 0] {
            pub -
            sec -
            crt -
            crs {
                # Store the current key

                if {[llength $subkey] > 0} {
                    lappend subkeys $subkey
                }
                if {[llength $subkeys] > 0} {
                    lappend key subkeys $subkeys
                }
                array set tmp $key
                if {[::info exists tmp(fingerprint)]} {
                    set keys($tmp(fingerprint)) $key
                    lappend res $tmp(fingerprint)
                }
                array unset tmp

                # Start a new key

                set st key
                set key {}
                set subkey {}
                set subkeys {}
            }
            sub -
            ssb {
                # Store the current subkey

                if {[llength $subkey] > 0} {
                    lappend subkeys $subkey
                }

                # Start a new subkey

                set st subkey
                set subkey {}
            }
            sig {
                # Signature
            }
        }
        switch -- $st {
            key {
                set key [concat $key [ParseRecord $fields]]
            }
            subkey {
                set subkey [concat $subkey [ParseRecord $fields]]
            }
        }
    }

    # Store the last key

    if {[llength $subkey] > 0} {
        lappend subkeys $subkey
    }
    if {[llength $subkeys] > 0} {
        lappend key subkeys $subkeys
    }
    array set tmp $key
    if {[::info exists tmp(fingerprint)]} {
        set keys($tmp(fingerprint)) $key
        lappend res $tmp(fingerprint)
    }

    return $res
}

proc ::gpg::ParseRecord {fields} {
    switch -- [lindex $fields 0] {
	pub -
	sec -
        crt -
        crs -
	sub -
	ssb {
            # pub: public key
            # sec: secret key
            # crt: X.509 certificate
            # crs: X.509 certificate and private key available
            # sub: subkey (secondary key)
            # ssb: secret subkey (secondary key)
            set result [Trust [lindex $fields 1]]
            lappend result length    [lindex $fields 2]
            lappend result algorithm [Algorithm [lindex $fields 3]]
            lappend result keyid     [lindex $fields 4]
            lappend result created   [lindex $fields 5]
            if {[lindex $fields 6] ne ""} {
                lappend result expire [lindex $fields 6]
            }
            # TODO
            lappend result owner-trust [lindex $fields 8]
            # TODO
            lappend result key-capability [lindex $fields 11]
            return $result
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

# ::gpg::ExecGPG --
#
#       Spawn a new gpg process adding several common arguments to a supplied
#       arguments list. Added arguments are --no-tty, --quiet, --output -,
#       --status-fd 2. If --batch doesn't belong to aruments list then
#       --command-fd 0 is also added. But if the proc CExecGPG exists then it
#       is called and its result is returned to a caller (with prepended empty
#       string to show that there's no temporary file to delete).
#
# Arguments:
#       token       A GPG context token created in ::gpg::context.
#       args        Any arguments for gpg (see gpg(1) manual page) except
#                   --status-fd and --command-fd which are added automatically.
#
# Result:
#       A list of opened pipes to a spawned process (with prepended temporary
#       file name which is to be deleted after gpg finishes its work). It
#       contains 5 or 6 elements: temporary file name, stdin, stdout, stderr,
#       status-fd, command-fd (optionally). The actual channels may be the
#       same (for example, stdin and command-fd are the same if CExecGPG
#       doesn't exist).
#
# Side effects:
#       A new gpg process is spawned. Also, if --decrypt or --verify options
#       are present in arguments list then a temporary file is created.

proc ::gpg::ExecGPG {token args} {
    Debug 1 $args

    # Add common --no-tty, --quiet, --output -, --charset utf-8 arguments

    set args [linsert $args 0 --no-tty --quiet --output - --charset utf-8]

    # Set --textmode option before calling CExecGPG to make it simpler.

    set textmode [Get $token -property textmode]

    if {$textmode} {
        set args [linsert $args 0 --textmode]
    } else {
        # This option is default, but add it to override value in
        # config file.
        set args [linsert $args 0 --no-textmode]
    }

    if {[::info commands [namespace current]::CExecGPG] ne ""} {

        # C-based GPG invocation will use pipes instead of temporary files,
        # so in case of decryption or verification of a detached signature
        # it returns an additional channel where we put the input string.

        if {[lsearch -exact $args --decrypt] >= 0 || \
                [lsearch -exact $args --verify] >= 0} {
            set input [lindex $args end]
            set args [lrange $args 0 end-1]

            set channels [eval CExecGPG [executable] $args]
            set input_fd [lindex $channels end]

            if {$textmode} {
                fconfigure $input_fd -translation crlf
            }

            puts -nonewline $input_fd $input
            close $input_fd

            return [linsert [lrange $channels 0 end-1] 0 ""]
        } else {
            return [linsert [eval CExecGPG [executable] $args] 0 ""]
        }
    }

    # For decryption or verification of a detached signature we use a
    # temporary file, so encrypted message has to be passed (and it's
    # passed as the last argument).

    if {[lsearch -exact $args --decrypt] >= 0} {
        set decrypt 1
        set verify 0
        set input [lindex $args end]
        set args [lrange $args 0 end-1]
    } elseif {[lsearch -exact $args --verify] >= 0} {
        set decrypt 0
        set verify 1
        set input [lindex $args end]
        set args [lrange $args 0 end-1]
    } else {
        set decrypt 0
        set verify 0
    }

    # Raise an error if there are dangerous arguments

    foreach arg $args {
        if {[string first < $arg] == 0 || [string first > $arg] == 0 || \
            [string first 2> $arg] == 0 || [string first | $arg] == 0 || \
            [string equal & $arg]} {

            return -code error \
                   [format "forbidden argument \"%s\" in exec call" $arg]
        }
    }

    # Create a temporary file for decryption or verification

    if {$decrypt || $verify} {
        set name_fd [TempFile]
        foreach {filename fd} $name_fd break

        if {$textmode} {
            fconfigure $fd -translation crlf
        }

        puts -nonewline $fd $input
        close $fd

        set args [linsert $args end $filename]
    } else {
        set filename ""
    }

    # In case of verification of a detached signature two channels are
    # necessary, so add stdin for signed input

    if {$verify} {
        set args [linsert $args end -]
    }

    # Add common --status-fd argument, and
    # --command-fd if there's no --batch option

    set args [linsert $args 0 --status-fd 2]

    if {[lsearch -exact $args --batch] < 0} {
        set args [linsert $args 0 --command-fd 0]
        set batch 0
    } else {
        set batch 1
    }

    set pList [pipe]
    foreach {pRead pWrite} $pList break

    set qList [pipe]
    foreach {qRead qWrite} $qList break
    fconfigure $qRead -encoding utf-8

    # Redirect stdout and stderr to pipes

    lappend args >@ $pWrite 2>@ $qWrite

    Debug 2 [linsert $args 0 [executable]]

    set fd [open |[linsert $args 0 [executable]] w]
    fconfigure $fd -translation binary -buffering none
    close $pWrite
    close $qWrite

    if {!$batch} {
        # Return channels in order: temporary file name, stdin, stdout,
        # stderr, status-fd, command-fd

        return [list $filename $fd $pRead $qRead $qRead $fd]
    } else {
        # Return channels in order: temporary file name, stdin, stdout,
        # stderr, status-fd

        return [list $filename $fd $pRead $qRead $qRead]
    }
}

# ::gpg::UseGPG --
#
#       Supply input to an already executed gpg process and interpret its
#       output.
#
# Arguments:
#       token       A GPG context token created in ::gpg::context.
#       operation   one of the "", verify, encrypt, decrypt, sign. It must be
#                   consistent with a corresponding option given to ExecGPG
#                   ("", --verify, --encrypt or --symmetric, --decrypt, --sign
#                   or --clearsign or --detach-sign).
#       channels    Open channels list as returned by ExecGPG.
#       input       Additional input to give to gpg process.
#
# Result:
#       An interpreted gpg output. Depending on the operation it is either
#       a verified signature, or an encrypted message, or a decrypted message
#       (with signature verification), or a signed message.
#
# Side effects:
#       A spawned gpg process finishes its work, and its IO channels are
#       closed. Also, a temporary file is removed if it was created in
#       ExecGPG.
#
# TODO:
#       Asynchronous processing (non-blocking channel)

proc ::gpg::UseGPG {token operation channels {input ""}} {
    variable Version
    variable keys

    foreach {filename stdin_fd stdout_fd stderr_fd status_fd command_fd} \
            $channels break

    switch -- $operation {
        "" -
        verify {
            # Here $input contains either a signature, or a signed material
            # if a signature is detached.
            puts -nonewline $stdin_fd $input
            catch {close $stdin_fd}
        }
    }

    # Collect signatures if any (if operation is decrypt or verify)

    set signatures {}
    array unset sig

    # Parse gpg status output

    while {[gets $status_fd line] >= 0} {
        Debug 2 $line
        set fields [split $line]

        if {[lindex $fields 0] ne "\[GNUPG:\]"} continue

        switch -- [lindex $fields 1] {
            BEGIN_ENCRYPTION { break }
            BEGIN_SIGNING { break }
            USERID_HINT {
                set userid_hint [join [lrange $fields 2 end]]
            }
            NEED_PASSPHRASE {
                if {![package vsatisfies $Version 2.0]} {
                    if {![::info exists hint]} {
                        set hint ENTER
                    } else {
                        set hint TRY_AGAIN
                    }
                    set pcb [Get $token -property passphrase-callback]
                    if {$pcb eq ""} {
                        # TODO: cleanup
                        return -code error "No passphrase"
                    }
                    set desc \
                        [join [list $hint $userid_hint \
                                    [join [lrange $fields 2 end] " "]] \
                              "\n"]
                    Debug 2 $desc
                    puts $command_fd \
                         [eval $pcb [list [list token $token \
                                                description $desc]]]
		    flush $command_fd
                }
            }
            NEED_PASSPHRASE_SYM {
                if {![package vsatisfies $Version 2.0]} {
                    set pcb [Get $token -property passphrase-callback]
                    if {$pcb eq ""} {
                        # TODO: cleanup
                        return -code error "No passphrase"
                    }
                    puts $command_fd \
                         [eval $pcb [list [list token $token \
                                                description ENTER]]]
		    flush $command_fd
                }
            }
            KEYEXPIRED {
                switch -- $operation {
                    "" -
                    verify {}
                    default {
                        # TODO: cleanup
                        return -code error "Key expired"
                    }
                }
            }
            KEYREVOKED {
                switch -- $operation {
                    "" -
                    verify {}
                    default {
                        # TODO: cleanup
                        return -code error "Key revoked"
                    }
                }
            }
            SIG_ID {
                # Start of a signature, so finish the previous
                # one if any and start a new one

                if {[llength [array names sig]] > 0} {
                    # Finish a signature
                    if {$sig(status) eq "good" && \
                            [llength $sig(summary)] == 1 && \
                            [lindex $sig(summary) 0] eq "green"} {
                        lappend sig(summary) valid
                    }
                    lappend signatures [array get sig]
                    array unset sig
                }

                # Start new signature
                array set sig [list status nosig validity unknown \
                                    summary {}]
            }
            GOODSIG {
                set sig(status) good
                set sig(keyid) [lindex $fields 2]
                set sig(userid) [join [lrange $fields 3 end]]
            }
            EXPSIG {
                set sig(status) expired
                set sig(keyid) [lindex $fields 2]
                set sig(userid) [join [lrange $fields 3 end]]
            }
            EXPKEYSIG {
                set sig(status) expiredkey
                set sig(keyid) [lindex $fields 2]
                set sig(userid) [join [lrange $fields 3 end]]
            }
            REVKEYSIG {
                set sig(status) revokedkey
                set sig(keyid) [lindex $fields 2]
                set sig(userid) [join [lrange $fields 3 end]]
            }
            BADSIG {
                set sig(status) bad
                lappend sig(summary) red
                set sig(keyid) [lindex $fields 2]
                set sig(userid) [join [lrange $fields 3 end]]
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
                    FindKeys $token --list-keys $sig(key)
                }
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
            NODATA -
            UNEXPECTED {
                set sig(status) nosig
            }
        }
    }

    # Finish the last signature (if any)

    if {[llength [array names sig]] > 0} {
        # Finish a signature
        if {$sig(status) eq "good" && \
                [llength $sig(summary)] == 1 && \
                [lindex $sig(summary) 0] eq "green"} {
            lappend sig(summary) valid
        }
        lappend signatures [array get sig]
        array unset sig
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
            # There's no signature
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

    switch -- $operation {
        encrypt -
        sign {
            # Supply message for decryption, encryption or signing

            puts -nonewline $stdin_fd $input
            catch {close $stdin_fd}

            if {![Get $token -property armor]} {
                fconfigure $stdout_fd -translation binary
            }

            set data [read $stdout_fd]
        }
        decrypt -
        "" {
            # "" means verifying non-detached signature, so gpg reports
            # the signed message to stdout.

            fconfigure $stdout_fd -translation binary
            set plaintext [read $stdout_fd]
            set data [list plaintext $plaintext status $status \
                           signatures $signatures]
        }
        verify {
            set data [list status $status signatures $signatures]
        }
    }

    # If gpg returns nonzero status or writes to stderr, close raises
    # an error. So, the catch is necessary.
    # TODO: Process the error

    catch {close $stdin_fd}
    catch {close $stdout_fd}
    catch {close $stderr_fd}
    catch {close $status_fd}
    catch {close $command_fd}

    if {$filename ne ""} {
        file delete -force -- $filename
    }

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
        return -code error "missing operation"
    }

    switch -- $op {
        add   { return [eval [list RecipientAdd   $token] $newArgs] }
        count { return [eval [list RecipientCount $token] $newArgs] }
        list  { return [eval [list RecipientList  $token] $newArgs] }
        default {
            return -code error \
                   [format "bad operation \"%s\":\
                            must be %s" $op [JoinOptions {add count list}]]
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
#       -validity val   (optional, defaults to unknown) An assigned validity.
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
            -name     { set name     $val }
            -validity { set validity $val }
            default {
                return -code error \
                       [format "bad option \"$s\":\
                                must be %s" $key [JoinOption {-operation
                                                              -name
                                                              -validity}]]
            }
        }
    }

    if {![::info exists name]} {
        return -code error "-name option must be provided"
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

# ::gpg::RecipentList --
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

# ::gpg::RecipentFullList --
#
#       Return list of pairs {recipient name, validity} for recipient token.
#
# Arguments:
#       token           A recipient token created by ::gpg::recipient.
#
# Result:
#       A list of added recipient names accompanied by validities.
#
# Side effects:
#       None.

proc ::gpg::RecipientFullList {token} {
    variable $token
    upvar 0 $token state

    return $state(recipients)
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
            return "[lindex $optList 0]"
        }
        2 {
            return "[lindex $optList 0] or [lindex $optList 1]"
        }
        default {
            return "[join [lrange $optList 0 end-1] {, }], or\
                    [lindex $optList end]"
        }
    }
}

# ::gpg::TempFile --
#
#       Create temporary file with random name and return it's name for
#       subsequent removing and channel. Code is borrowed from
#       http://wiki.tcl.tk/772
#
# Arguments:
#       None.
#
# Result:
#       A two element list with file name as the first element and file
#       handle as the second, or an error if a file cannot be created.
#
# Side effects:
#       A file is created and opened for reading and writing.

proc ::gpg::TempFile {} {
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
    if {$fd eq ""} {
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
