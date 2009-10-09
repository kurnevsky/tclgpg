# tclgpg.tcl --
#
#        Tcl interface to GNU Privacy Guard.
#
# Copyright (c) 2008-2009 Sergei Golovan <sgolovan@nes.ru>
#
# See the file "license.terms" for information on usage and redistribution
# of this file, and for a DISCLAMER OF ALL WARRANTIES.
#
# $Id$

package require Tcl 8.4

if {[info commands ::gpg::CExecGPG] eq ""} {
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
    return -code error "GnuPG 2 cannot be used without gpg-agent"
}

namespace eval ::gpg {
    variable validities [list unknown undefined never marginal full ultimate]

    variable Version $::gpgVersion
    unset ::gpgVersion

    # Variable to store public keys
    variable keys

    variable debug 0
}

# ::gpg::executable --
#
#       Find a GnuPG executable in the system using the same rules [exec] does.
#
# Arguments:
#       None.
#
# Result:
#       Full pathname of the first occurence of the GnuPG executable found
#       or an empty string if the search yielded no results.
#
# Side effects:
#       Updates the global Tcl array auto_execs on success (see library(3tcl)).

proc ::gpg::executable {} {
    lindex [auto_execok gpg] 0
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

    set state(id) $id

    # Default settings
    set state(armor) false
    set state(textmode) false
    set state(encoding) [encoding system]
    set state(passphrase-encoding) [encoding system]

    proc $token {args} "eval {[namespace current]::Exec $token} \$args"

    return $token
}

# ::gpg::free --
#
#       Unset state variable corresponding to a context token and destroy
#       the token procedure.
#
# Arguments:
#       token       A GPG context token created in ::gpg::context.
#
# Result
#       An empty string.
#
# Side effects:
#       A state variable and token procedure are destroyed.

proc ::gpg::Free {token} {
    variable $token
    upvar 0 $token state

    rename $token ""

    catch {unset state}
    return
}

# ::gpg::Exec --
#
#       Execute a GPG context operation. This procedure is invoked when a user
#       calls [$token operation ...].
#
# Arguments:
#       token       A GPG context token created in ::gpg::context.
#       operation   An operation to perform
#       args        Arguments serialized array. The arguments are operation-
#                   dependent.
#
# Result:
#       The result of a corresponding operation.
#
# Side effects:
#       The side effects of a corresponding operation.

proc ::gpg::Exec {token operation args} {
    switch -- $operation {
        cancel    { set res [eval [list Cancel   $token] $args] }
        wait      { set res [eval [list Wait     $token] $args] }
        set       { set res [eval [list Set      $token] $args] }
        unset     { set res [eval [list Unset    $token] $args] }
        list-keys { set res [eval [list ListKeys $token] $args] }
        info-key  { set res [eval [list InfoKey  $token] $args] }
        encrypt   { set res [eval [list Encrypt  $token] $args] }
        sign      { set res [eval [list Sign     $token] $args] }
        verify    { set res [eval [list Verify   $token] $args] }
        decrypt   { set res [eval [list Decrypt  $token] $args] }
        free      { set res [eval [list Free     $token] $args] }
        default   {
            return -code error \
                   [format "unknown operation \"%s\":\
                            must be %s" $operation \
                            [JoinOptions {cancel wait set unset encrypt decrypt
                                          sign verify list-keys info-key
                                          free}]]
        }
    }

    if {![string equal $operation free]} {
        set state(last-op-info) $operation
    }
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
#       Set a given GPG context property to a given value or query GPG context
#       property.
#
# Arguments:
#       token           A GPG context token created in ::gpg::context.
#       -property prop  A property name.
#       -value value    (optional) A value to set. If missing then property
#                       is set to an empty string which essentially means it's
#                       unset.
#
# Result:
#       Property value in case of success, or an error if a property is missing
#       or unknown.
#
# Side effects:
#       A state variable corresponding to a given property is set.

proc ::gpg::Set {token args} {
    variable properties
    variable $token
    upvar 0 $token state

    Debug 2 "$token $args"

    if {[llength $args] != 2 && [llength $args] != 4} {
        return -code error \
            "wrong # args: should be set -property propertyName\
                ?-value value?"
    }

    foreach {key val} $args {
        switch -- $key {
            -property { set prop  $val }
            -value    { set value $val }
            default   {
                return -code error \
                       [format "unknown option \"%s\":\
                                must be %s" $key [JoinOptions {-property
                                                               -value}]]
            }
        }
    }

    variable properties [list armor textmode passphrase-callback \
                              signers encoding passphrase-encoding \
                              last-op-info]

    if {![info exists prop]} {
        return -code error \
               [format "missing property:\
                        must be %s" [JoinOptions $properties]]
    } elseif {[lsearch -exact $properties $prop] >= 0} {
        if {![info exists value]} {
            if {[info exists state($prop)]} {
                return $state($prop)
            } else {
                return -code error [format "property \"%s\" is not set" $prop]
            }
        } else {
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
            return $state($prop)
        }
    } else {
        return -code error \
               [format "unknown property \"%s\":\
                        must be %s" $prop [JoinOptions $properties]]
    }
}

# ::gpg::Unset --
#
#       Unset a given GPG context property.
#
# Arguments:
#       token           A GPG context token created in ::gpg::context.
#       -property prop  A property name.
#
# Result:
#       Empty string or error if property is missing or unknown.
#
# Side effects:
#       Property variable is unset.

proc ::gpg::Unset {token args} {
    variable $token
    upvar 0 $token state

    Debug 2 "$token $args"

    if {[llength $args] != 2} {
        return -code error \
            "wrong # args: should be unset -property propertyName"
    }

    foreach {key val} $args {
        switch -- $key {
            -property { set prop $val }
            default   {
                return -code error \
                       [format "unknown option \"%s\":\
                                must be %s" $key [JoinOptions {-property}]]
            }
        }
    }

    set properties [list armor textmode passphrase-callback \
                         signers encoding passphrase-encoding]

    if {![info exists prop]} {
        return -code error \
               [format "missing property:\
                        must be %s" [JoinOptions $properties]]
    } elseif {[lsearch -exact $properties $prop] >= 0} {
        # Restoring the default settings or unsetting the property

        switch -- $prop {
            armor -
            textmode {
                set state($prop) false
            }
            encoding -
            passphrase-encoding {
                set state($prop) [encoding system]
            }
            default {
                catch {unset state($prop)}
            }
        }
    } else {
        return -code error \
               [format "unknown property \"%s\":\
                        must be %s" $prop [JoinOptions $properties]]
    }

    return
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
    set commands {}
    foreach {key val} $args {
        switch -- $key {
            -input   { set input $val }
            -mode    { set mode  $val }
            -command { set commands [list $val] }
            default {
                return -code error \
                       [format "unknown option \"%s\":\
                                must be %s" $key [JoinOptions {-input
                                                               -mode
                                                               -command}]]
            }
        }
    }

    if {![info exists input]} {
        return -code error "missing input to sign"
    }

    set params {}

    switch -- $mode {
        normal  {
            lappend params --sign
            set operation sign
        }
        detach  {
            lappend params --detach-sign
            set operation detach-sign
        }
        clear   {
            lappend params --clearsign
            set operation clearsign
        }
        default {
            return -code error \
                   [format "unknown mode \"%s\":\
                            must be %s" $mode [JoinOptions {normal
                                                            detach
                                                            clear}]]
        }
    }

    array set tmp {}
    if {[catch {Set $token -property signers} signers]} {
        set signers {}
    }
    foreach key $signers {
        array unset tmp
        array set tmp [InfoKey $token -key $key]
        lappend params -u $tmp(keyid)
    }

    set gpgChannels [eval ExecGPG $token $operation $params --]
    return [UseGPG $token sign $commands $gpgChannels $input]
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
    set commands {}
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
            -command {
                set commands [list $val]
            }
            default {
                return -code error \
                       [format "unknown option \"%s\":\
                                must be %s" $key [JoinOptions {-input
                                                               -recipients
                                                               -sign
                                                               -command}]]
            }
        }
    }

    if {![info exists input]} {
        return -code error "missing input to encrypt"
    }

    set params {}

    if {$sign} {
        lappend params --sign
        array set tmp {}
        if {[catch {Set $token -property signers} signers]} {
            set signers {}
        }
        foreach key $signers {
            array unset tmp
            array set tmp [InfoKey $token -key $key]
            lappend params -u $tmp(keyid)
        }
    }

    if {[info exists recipients]} {
        if {[RecipientCount $recipients] == 0} {
            return -code error "no recipients in token"
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

    set gpgChannels [eval ExecGPG $token encrypt $params --]
    return [UseGPG $token encrypt $commands $gpgChannels $input]
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

    set commands {}
    foreach {key val} $args {
        switch -- $key {
            -signature { set signature $val }
            -input     { set input     $val }
            -command   { set commands [list $val] }
            default    {
                return -code error \
                       [format "unknown option \"%s\":\
                                must be %s" $key [JoinOptions {-signature
                                                               -input
                                                               -command}]]
            }
        }
    }

    if {![info exists signature]} {
        return -code error "missing signature to verify"
    }

    if {[info exists input]} {
        set gpgChannels [ExecGPG $token verify --verify -- $signature]
        return [UseGPG $token verify $commands $gpgChannels $input]
    } else {
        set gpgChannels [ExecGPG $token "" --]
        return [UseGPG $token "" $commands $gpgChannels $signature]
    }
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
    set commands {}
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
            -command {
                set commands [list $val]
            }
            default {
                return -code error \
                       [format "unknown option \"%s\":\
                                must be %s" $key [JoinOptions {-input
                                                               -checkstatus
                                                               -command}]]
            }
        }
    }

    if {![info exists input]} {
        return -code error "missing input to decrypt"
    }

    if {$checkstatus} {
        set gpgChannels [ExecGPG $token decrypt-check --decrypt -- $input]
        return [UseGPG $token decrypt-check $commands $gpgChannels]
    } else {
        set gpgChannels [ExecGPG $token decrypt --decrypt -- $input]
        return [UseGPG $token decrypt $commands $gpgChannels]
    }
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
#       -command            A command to call back with a list of keys appended.
#                           If present then an asynchronous mode is enabled.
#
# Result:
#       A list of matching keys in synchronous mode or a token (stdout channel
#       name of the executed GPG process) in asynchronous mode.
#
# Side effects:
#       A global keys array is populated by keys which match given patterns.

proc ::gpg::ListKeys {token args} {
    variable $token
    upvar 0 $token state

    set patterns {}
    set operation --list-keys
    set commands {}

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
            -command {
                set commands [list $val]
            }
            default {
                return -code error \
                       [format "unknown option \"%s\":\
                                must be %s" $key [JoinOptions {-patterns
                                                               -secretonly
                                                               -command}]]
            }
        }
    }

    return [FindKeys $token $operation $commands $patterns]
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
                             must be %s" $key [JoinOptions {-key}]]
            }
        }
    }

    if {![info exists fingerprint]} {
        return -code error "missing key"
    }

    if {[info exists keys($fingerprint)]} {
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
#       commands            A list of commands to call back (its length may be
#                           0 or 1). If it's empty then a synchronous mode is
#                           enabled.
#       patterns            A list of patterns to search for in keys available
#                           to GnuPG. Patterns may contain key ID, fingerprint,
#                           user ID etc. See gpg(1) manual page for details.
#
# Result:
#       A list of keys which match given patterns in a synchronous mode or a
#       stdout channel name of the executed GPG process in asynchronous mode.
#
# Side effects:
#       A global keys array is populated by keys which match given patterns.

proc ::gpg::FindKeys {token operation commands patterns} {

    set channels [eval ExecGPG $token list-keys \
                                      --batch \
                                      --with-colons \
                                      --fixed-list-mode \
                                      --with-fingerprint \
                                      --with-fingerprint \
                                      $operation -- $patterns]

    set channels [lrange $channels 1 end]

    # Configure stdout of executed GPG process
    set stdout_fd [lindex $channels 1]

    if {[llength $commands] == 0} {
        # Synchronous mode, so make channel blocking and parse its contents

        fconfigure $stdout_fd -blocking true
        return [Parse $channels $commands]
    } else {
        # Asynchronous mode, so make channel nonblocking and parse its contents
        # eventually
        fconfigure $stdout_fd -blocking false
        fileevent $stdout_fd readable [namespace code [list Parse $channels $commands]]
        return $stdout_fd
    }
}

proc ::gpg::Parse {channels commands} {
    variable keys

    # This proc may be called several times as a fileevent, so we have to
    # maintain a state.

    set stdout_fd [lindex $channels 1]
    variable $stdout_fd
    upvar 0 $stdout_fd state

    if {![info exists state(res)]} {
        set state(res) {}
        set state(key) {}
        set state(subkey) {}
        set state(subkeys) {}
        set state(st) ""
        set state(channels) $channels
        set state(commands) $commands
    }

    while {[gets $stdout_fd line] >= 0} {
        set fields [split $line ":"]
        switch -- [lindex $fields 0] {
            pub -
            sec -
            crt -
            crs {
                # Store the current key

                if {[llength $state(subkey)] > 0} {
                    lappend state(subkeys) $state(subkey)
                }
                if {[llength $state(subkeys)] > 0} {
                    lappend state(key) subkeys $state(subkeys)
                }
                array set tmp $state(key)
                if {[info exists tmp(fingerprint)]} {
                    set keys($tmp(fingerprint)) $state(key)
                    lappend state(res) $tmp(fingerprint)
                }
                array unset tmp

                # Start a new key

                set state(st) key
                set state(key) {}
                set state(subkey) {}
                set state(subkeys) {}
            }
            sub -
            ssb {
                # Store the current subkey

                if {[llength $state(subkey)] > 0} {
                    lappend state(subkeys) $state(subkey)
                }

                # Start a new subkey

                set state(st) subkey
                set state(subkey) {}
            }
            sig {
                # Signature
            }
        }
        switch -- $state(st) {
            key {
                set state(key) [concat $state(key) [ParseRecord $fields]]
            }
            subkey {
                set state(subkey) [concat $state(subkey) [ParseRecord $fields]]
            }
        }
    }

    if {[eof $stdout_fd] || [llength $commands] == 0} {
        # Store the last key

        if {[llength $state(subkey)] > 0} {
            lappend state(subkeys) $state(subkey)
        }
        if {[llength $state(subkeys)] > 0} {
            lappend state(key) subkeys $state(subkeys)
        }
        array set tmp $state(key)
        if {[info exists tmp(fingerprint)]} {
            set keys($tmp(fingerprint)) $state(key)
            lappend state(res) $tmp(fingerprint)
        }

        set res $state(res)
        unset state

        foreach ch $channels {
            catch {close $ch}
        }

        if {[llength $commands] == 0} {
            return $res
        } else {
            uplevel #0 [lindex $commands 0] [list ok $res]
        }
    }

    return
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
#       operation   one of the "", verify, encrypt, decrypt or decrypt-check,
#                   sign, or list-keys. It must be consistent with a
#                   corresponding option given in args ("", --verify, --encrypt
#                   or --symmetric, --decrypt, or --sign or --clearsign or
#                   --detach-sign, or --list-keys).
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

proc ::gpg::ExecGPG {token operation args} {
    Debug 1 $args

    # Add common --no-tty, --quiet, --output -, --charset utf-8 arguments

    set args [linsert $args 0 --no-tty --quiet --output - --charset utf-8]

    # Set --armor option before calling CExecGPG

    set armor [Set $token -property armor]

    switch -- $operation {
        encrypt -
        sign -
        detach-sign {
            # Armoring output makes sense only for sign and encrypt operations.

            if {$armor} {
                set args [linsert $args 0 --armor]
            } else {
                set args [linsert $args 0 --no-armor]
            }
        }
    }

    # Set --textmode option before calling CExecGPG to make it simpler.

    set textmode [Set $token -property textmode]

    if {$textmode} {
        set args [linsert $args 0 --textmode]
    } else {
        # This option is default, but add it to override value in
        # config file.
        set args [linsert $args 0 --no-textmode]
    }

    # Set proper encoding

    set encoding [Set $token -property encoding]

    # For decryption or verification of a detached signature we use a
    # temporary file or a pipe, so encrypted message has to be passed
    # (and it's passed as the last argument).

    switch -- $operation {
        decrypt -
        decrypt-check -
        verify {
            set input [lindex $args end]
            set args [lrange $args 0 end-1]
        }
    }

    if {[info commands [namespace current]::CExecGPG] ne ""} {

        set channels [eval CExecGPG [executable] $args]

        # C-based GPG invocation uses pipes instead of temporary files,
        # so in case of decryption or verification of a detached signature
        # it returns an additional channel where we put the input string.

        switch -- $operation {
            decrypt -
            decrypt-check -
            verify {
                set input_fd [lindex $channels end]

                # Encrypted material and/or detached signature are both either
                # in ASCII (if armored) or binary (if not armored). For both
                # cases binary translation is fine.

                fconfigure $input_fd -translation binary

                puts -nonewline $input_fd $input
                close $input_fd

                set channels [lrange $channels 0 end-1]
            }
        }

        set filename ""

    } else {

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

        switch -- $operation {
            decrypt -
            decrypt-check -
            verify {
                foreach {filename input_fd} [TempFile] break

                # Encrypted material and/or detached signature are both either
                # in ASCII (if armored) or binary (if not armored). For both
                # cases binary translation is fine.

                fconfigure $input_fd -translation binary

                puts -nonewline $input_fd $input
                close $input_fd

                set args [linsert $args 0 --enable-special-filenames]
                set args [linsert $args end $filename]
            }
            default {
                set filename ""
            }
        }

        # In case of verification of a detached signature two channels are
        # necessary, so add stdin for signed input

        switch -- $operation {
            verify {
                set args [linsert $args end -]
            }
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

        # Redirect stdout and stderr to pipes

        lappend args >@ $pWrite 2>@ $qWrite

        Debug 2 [linsert $args 0 [executable]]

        set fd [open |[linsert $args 0 [executable]] w]
        close $pWrite
        close $qWrite

        if {!$batch} {
            # Return channels in order: temporary file name, stdin, stdout,
            # stderr, status-fd, command-fd

            set channels [list $fd $pRead $qRead $qRead $fd]
        } else {
            # Return channels in order: temporary file name, stdin, stdout,
            # stderr, status-fd

            set channels [list $fd $pRead $qRead $qRead]
        }
    }

    # Configuring input/output channels

    if {[llength $channels] == 5} {
        # command-fd and stdin are the same channel if CExecGPG is unavailable,
        # so, configure its encoding right before use
        fconfigure [lindex $channels 4] -buffering none
    }

    # stdin
    fconfigure [lindex $channels 0] -encoding $encoding -buffering none

    # stdout
    switch -- $operation {
        list-keys {
            fconfigure [lindex $channels 1] -encoding utf-8
        }
        sign -
        detach-sign -
        encrypt {
            if {!$armor} {
                fconfigure [lindex $channels 1] -translation binary
            } else {
                fconfigure [lindex $channels 1] -encoding $encoding
            }
        }
        default {
            fconfigure [lindex $channels 1] -encoding $encoding
        }
    }

    # stderr is always in UTF-8
    fconfigure [lindex $channels 2] -encoding utf-8

    # status-fd is always in UTF-8
    fconfigure [lindex $channels 3] -encoding utf-8

    # Insert a temporary file name at the beginning of channels list

    return [linsert $channels 0 $filename]
}

# ::gpg::UseGPG --
#
#       Supply input to an already executed gpg process and interpret its
#       output.
#
# Arguments:
#       token       A GPG context token created in ::gpg::context.
#       operation   one of the "", verify, encrypt, decrypt or decrypt-check,
#                   or sign. It must be consistent with a corresponding option
#                   given to ExecGPG ("", --verify, --encrypt or --symmetric,
#                   --decrypt, or --sign or --clearsign or --detach-sign).
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

proc ::gpg::UseGPG {token operation commands channels {input ""}} {
    set stdin_fd  [lindex $channels 1]
    set status_fd [lindex $channels 4]

    switch -- $operation {
        "" {
            # Here $input contains a signature, or a clear signature, which
            # require different encodings, so we have to use some heuristics

            if {![string match "-----BEGIN PGP SIGNED MESSAGE-----*" $input]} {
                fconfigure $stdin_fd -translation binary -buffering none
            }

            puts -nonewline $stdin_fd $input
            catch {close $stdin_fd}
        }
        verify {
            # Here $input contains a signed material (verifying a detached
            # signature)

            puts -nonewline $stdin_fd $input
            catch {close $stdin_fd}
        }
    }

    if {[llength $commands] == 0} {
        # Synchronous mode, so make channel blocking and parse its contents

        fconfigure $status_fd -blocking true
        return [ParseGPG $token $operation $commands $channels $input]
    } else {
        # Asynchronous mode, so make channel nonblocking and parse its contents
        # eventually

        fconfigure $status_fd -blocking false
        fileevent $status_fd readable \
                  [namespace code [list ParseGPG $token $operation $commands \
                                                 $channels $input]]
        return $status_fd
    }
}

proc ::gpg::ParseGPG {token operation commands channels input} {
    variable Version
    variable keys

    foreach {filename stdin_fd stdout_fd stderr_fd status_fd command_fd} \
            $channels break

    # This proc may be called several times as a fileevent, so we have to
    # maintain a state.

    variable $status_fd
    upvar 0 $status_fd state

    # Collect signatures if any (if operation is decrypt-check or verify)

    if {![info exists state(signatures)]} {
        set state(signatures) {}
    }

    # Parse gpg status output

    set eof 0
    while {[gets $status_fd line] >= 0} {
        Debug 2 $line
        set fields [split $line]

        if {[lindex $fields 0] ne "\[GNUPG:\]"} continue

        switch -- [lindex $fields 1] {
            BEGIN_ENCRYPTION -
            BEGIN_SIGNING {
                set eof 1
                break
            }
            USERID_HINT {
                set state(userid_hint) [join [lrange $fields 3 end]]
            }
            NEED_PASSPHRASE {
                set state(badpassphrase) 0
                if {![package vsatisfies $Version 2.0]} {
                    if {![info exists state(hint)]} {
                        set state(hint) enter
                    } else {
                        set state(hint) try_again
                    }
                    if {[catch {Set $token -property passphrase-callback} pcb]} {
                        FinishWithError $channels $commands "No passphrase"
                        return
                    }
                    set arglist [list token $token \
                                      hint $state(hint) \
                                      userid $state(userid_hint) \
                                      keyid [lindex $fields 2] \
                                      subkeyid [lindex $fields 3]]
                    Debug 2 $arglist
                    if {[catch {eval $pcb [list $arglist]} passphrase]} {
                        FinishWithError $channels $commands "No passphrase"
                        return
                    } else {
                        # Passphrase encoding may differ from message encoding,
                        # so we have to save command-fd encoding in case when
                        # command-fd and stdin are the same channel.

                        set encoding [fconfigure $command_fd -encoding]
                        fconfigure $command_fd \
                            -encoding [Set $token -property passphrase-encoding]
                        puts $command_fd $passphrase
                        flush $command_fd
                        fconfigure $command_fd -encoding $encoding
                    }
                }
            }
            NEED_PASSPHRASE_SYM {
                set state(badpassphrase) 0
                if {![package vsatisfies $Version 2.0]} {
                    if {[catch {Set $token -property passphrase-callback} pcb]} {
                        FinishWithError $channels $commands "No passphrase"
                        return
                    }
                    if {[catch {
                            eval $pcb [list [list token $token \
                                                  hint enter]]
                         } passphrase]} {
                        FinishWithError $channels $commands "No passphrase"
                        return
                    } else {
                        # Passphrase encoding may differ from message encoding,
                        # so we have to save command-fd encoding in case when
                        # command-fd and stdin are the same channel.

                        set encoding [fconfigure $command_fd -encoding]
                        fconfigure $command_fd \
                            -encoding [Set $token -property passphrase-encoding]
                        puts $command_fd $passphrase
                        flush $command_fd
                        fconfigure $command_fd -encoding $encoding
                    }
                }
            }
            BAD_PASSPHRASE {
                set state(badpassphrase) 1
            }
            DECRYPTION_FAILED {
                FinishWithError $channels $commands "Decryption failed"
                return
            }
            KEYEXPIRED {
                switch -- $operation {
                    "" -
                    verify {}
                    default {
                        FinishWithError $channels $commands "Key expired"
                        return
                    }
                }
            }
            KEYREVOKED {
                switch -- $operation {
                    "" -
                    verify {}
                    default {
                        FinishWithError $channels $commands "Key revoked"
                        return
                    }
                }
            }
            SIG_ID {
                # Start of a signature, so finish the previous
                # one if any and start a new one

                if {[llength [array names state sig:*]] > 0} {
                    # Finish a signature
                    if {$state(sig:status) eq "good" && \
                            [llength $state(sig:summary)] == 1 && \
                            [lindex $state(sig:summary) 0] eq "green"} {
                        lappend state(sig:summary) valid
                    }
                    lappend state(signatures) [array get state sig:*]
                    array unset state sig:*
                }

                # Start new signature
                array set state [list sig:status nosig sig:validity unknown \
                                      sig:summary {}]
            }
            GOODSIG {
                set state(sig:status) good
                set state(sig:keyid) [lindex $fields 2]
                set state(sig:userid) [join [lrange $fields 3 end]]
            }
            EXPSIG {
                set state(sig:status) expired
                set state(sig:keyid) [lindex $fields 2]
                set state(sig:userid) [join [lrange $fields 3 end]]
            }
            EXPKEYSIG {
                set state(sig:status) expiredkey
                set state(sig:keyid) [lindex $fields 2]
                set state(sig:userid) [join [lrange $fields 3 end]]
            }
            REVKEYSIG {
                set state(sig:status) revokedkey
                set state(sig:keyid) [lindex $fields 2]
                set state(sig:userid) [join [lrange $fields 3 end]]
            }
            BADSIG {
                set state(sig:status) bad
                lappend state(sig:summary) red
                set state(sig:keyid) [lindex $fields 2]
                set state(sig:userid) [join [lrange $fields 3 end]]
            }
            ERRSIG {
                switch -- [lindex $fields 7] {
                    9 {
                        set state(sig:status) nokey
                    }
                    default {
                        set state(sig:status) error
                    }
                }
                set state(sig:keyid) [lindex $fields 2]
            }
            VALIDSIG {
                set state(sig:fingerprint) [lindex $fields 2]
                set state(sig:created) [lindex $fields 4]
                if {[lindex $fields 5] != 0} {
                    set state(sig:expires) [lindex $fields 5]
                }
                set state(sig:key) [lindex $fields 11]
                if {![info exists keys($state(sig:key))]} {
                    FindKeys $token --list-keys {} $state(sig:key)
                }
            }
            TRUST_UNDEFINED {
                set state(sig:validity) unknown
            }
            TRUST_NEVER {
                set state(sig:validity) never
                switch -- $state(sig:status) {
                    good -
                    expired -
                    expiredkey {
                        lappend state(sig:summary) red
                    }
                }
            }
            TRUST_MARGINAL {
                set state(sig:validity) marginal
            }
            TRUST_FULLY -
            TRUST_ULTIMATE {
                set state(sig:validity) full
                switch -- $state(sig:status) {
                    good -
                    expired -
                    expiredkey {
                        lappend state(sig:summary) green
                    }
                }
            }
            NODATA -
            UNEXPECTED {
                set state(sig:status) nosig
            }
            INV_RECP {
                switch -- [lindex $fields 2] {
                    0 - 1 - 2 {
                        FinishWithError $channels $commands "Public key not found"
                        return
                    }
                    default {
                        FinishWithError $channels $commands "Unusable public key"
                        return
                    }
                }
            }
        }
    }

    if {$eof || [eof $status_fd] || [llength $commands] == 0} {
        if {[info exists state(badpassphrase)] && $state(badpassphrase)} {
            FinishWithError $channels $commands "Bad passphrase"
            return
        }

        set data [FinishGPG $token $operation $channels $input]

        CleanupGPG $channels

        if {[llength $commands] == 0} {
            return $data
        } else {
            uplevel #0 [lindex $commands 0] [list ok $data]
        }
    }

    return
}

proc ::gpg::FinishWithError {channels commands error} {
    CleanupGPG $channels
    if {[llength $commands] == 0} {
        return -code error $error
    } else {
        uplevel #0 [lindex $commands 0] [list error $error]
        return
    }
}

proc ::gpg::FinishGPG {token operation channels input} {
    Debug 2 "$token $operation $channels $input"

    foreach {filename stdin_fd stdout_fd stderr_fd status_fd command_fd} \
            $channels break

    variable $status_fd
    upvar 0 $status_fd state

    # Finish the last signature (if any)

    if {[llength [array names state sig:*]] > 0} {
        # Finish a signature
        if {$state(sig:status) eq "good" && \
                [llength $state(sig:summary)] == 1 && \
                [lindex $state(sig:summary) 0] eq "green"} {
            lappend state(sig:summary) valid
        }
        set signature {}
        foreach {key val} [array get state sig:*] {
            lappend signature [string range $key 4 end] $val
        }
        lappend state(signatures) $signature
        array unset state sig:*
    }

    set statuses {}
    foreach s $state(signatures) {
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
            set status diff
        }
    }

    switch -- $operation {
        encrypt -
        sign {
            # Supply message for encryption or signing

            puts -nonewline $stdin_fd $input
            catch {close $stdin_fd}

            set data [read $stdout_fd]
        }
        decrypt {
            set plaintext [read $stdout_fd]
            set data [list plaintext $plaintext]
        }
        decrypt-check -
        "" {
            # "" means verifying non-detached signature, so gpg reports
            # the signed message to stdout.

            set plaintext [read $stdout_fd]
            set data [list plaintext $plaintext status $status \
                           signatures $state(signatures)]
        }
        verify {
            set data [list status $status signatures $state(signatures)]
        }
    }

    return $data
}

proc ::gpg::CleanupGPG {channels} {
    Debug 2 $channels

    foreach {filename stdin_fd stdout_fd stderr_fd status_fd command_fd} \
            $channels break

    variable $status_fd
    upvar 0 $status_fd state

    # If gpg returns nonzero status or writes to stderr, close raises
    # an error. So, the catch is necessary.
    # TODO: Process the error

    catch {close $stdin_fd}
    catch {close $stdout_fd}
    catch {close $stderr_fd}
    catch {close $status_fd}
    catch {close $command_fd}

    unset state

    if {$filename ne ""} {
        file delete -force -- $filename
    }

    # Clean up zombie which tclsh leaves when executes gpg in the background
    catch {exec {}}

    return
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

    if {![info exists rid]} {
        set rid 0
    }

    set token [namespace current]::recipient[incr rid]
    variable $token
    upvar 0 $token state

    set state(recipients) {}

    proc $token {args} "eval {[namespace current]::RecipientExec $token} \$args"

    return $token
}

# ::gpg::RecipientFree --
#
#       Unset state variable and a procedure corresponding to a recipient token.
#
# Arguments:
#       token       A recipient context token created in ::gpg::recipient.
#
# Result
#       An empty string.
#
# Side effects:
#       A state variable and token procedure are destroyed.

proc ::gpg::RecipientFree {token} {
    variable $token
    upvar 0 $token state

    rename $token ""

    catch {unset state}
    return
}

# ::gpg::RecipientExec --
#
#       Execute a recipient operation. This procedure is invoked when a user
#       calls [$token operation ...] for a recipient token.
#
# Arguments:
#       token       A recipient token created in ::gpg::recipient.
#       operation   A performed operation.
#       args        Arguments serialized array. The arguments are operation-
#                   dependent.
#
# Result:
#       The result of a corresponding operation.
#
# Side effects:
#       The side effects of a corresponding operation.

proc ::gpg::RecipientExec {token operation args} {
    switch -- $operation {
        add   { return [eval [list RecipientAdd   $token] $args] }
        list  { return [eval [list RecipientList  $token] $args] }
        free  { return [eval [list RecipientFree  $token] $args] }
        default {
            return -code error \
                   [format "bad operation \"%s\":\
                            must be %s" $operation [JoinOptions {add list
                                                                 free}]]
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
                                must be %s" $key [JoinOption {-name
                                                              -validity}]]
            }
        }
    }

    if {![info exists name]} {
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

# ::gpg::RecipientCount --
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

# ::gpg::RecipientList --
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

# ::gpg::RecipientFullList --
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
        puts "[lindex [info level -1] 0]: $msg"
    }

    return
}

# vim:ft=tcl:ts=8:sw=4:sts=4:et
