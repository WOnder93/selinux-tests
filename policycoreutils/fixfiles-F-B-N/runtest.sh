#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/selinux/Sanity/fixfiles
#   Description: Tests fixfiles -F | -B | -N options
#   Author: Petr Lautrbach <plautrba@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2019 Red Hat, Inc.
#
#   This program is free software: you can redistribute it and/or
#   modify it under the terms of the GNU General Public License as
#   published by the Free Software Foundation, either version 2 of
#   the License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE.  See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program. If not, see http://www.gnu.org/licenses/.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Include Beaker environment
. /usr/bin/rhts-environment.sh || exit 1
. /usr/share/beakerlib/beakerlib.sh || exit 1

PACKAGE="policycoreutils"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm $PACKAGE
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlFileBackup "/.autorelabel"
        rlRun "rm -f /.autorelabel"
    rlPhaseEnd

    rlPhaseStartTest "fixfiles onboot"
        rlRun "fixfiles onboot"
        rlAssertExists "/.autorelabel"
        WC=`wc -c /.autorelabel | cut -f 1 -d " "`
        rlAssertEquals "/.autorelabel is empty" $WC 0

        rlRun "fixfiles -F onboot"
        rlRun "grep -- '^-F *\$' /.autorelabel"

        rlRun "fixfiles -B onboot"
        rlRun "grep -E -- '-N [0-9]{4}-[0-9]{2}-[0-9]{2}' /.autorelabel"

        rlRun "fixfiles -F -B onboot"
        rlRun "grep -E -- '-F -N [0-9]{4}-[0-9]{2}-[0-9]{2}' /.autorelabel"

        rlRun "rm -f /.autorelabel"
    rlPhaseEnd

    rlPhaseStartCleanup
        rlFileRestore
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
