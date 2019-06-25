#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/libselinux/Sanity/python-bindings
#   Description: Import selinux python module, check its metadata
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

PACKAGE="python3-libselinux"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm $PACKAGE
        rlAssertRpm python3-pip
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
    rlPhaseEnd

    rlPhaseStartTest "Check rpm and module metadata versions"
        rlRun "RpmVersion=\$(rpm -q --qf 'Version: %{version}' python3-libselinux)"
        rlRun "PipVersion=\$(pip3 show selinux | grep Version)"
        rlAssertEquals "Is the python3-libselinux version same as the version of python selinux module" "$RpmVersion" "$PipVersion"
    rlPhaseEnd

    rlPhaseStartTest "Import selinux module and try selinux.is_selinux_enabled()"
        rlRun "python3 -c 'import selinux'" 0
	rlRun "python3 -c 'import selinux; rc = selinux.is_selinux_enabled(); sys.exit(rc)'" 0,1
	rlRun "PYTHON_SELINUX_ENABLED=$?"
	if selinuxenabled; then
	    rlAssertEquals "SELinux is enabled" $PYTHON_SELINUX_ENABLED 1
	else
	    rlAssertNotEquals "SELinux is disabled" $PYTHON_SELINUX_ENABLED 0
	fi
    rlPhaseEnd

    rlPhaseStartCleanup
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
