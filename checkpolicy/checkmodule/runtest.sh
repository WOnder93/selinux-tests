#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/checkpolicy/Sanity/checkmodule
#   Description: runs checkmodule with various options to find out if it behaves correctly
#   Author: Milos Malik <mmalik@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2009 Red Hat, Inc. All rights reserved.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Include rhts environment
. /usr/bin/rhts-environment.sh
. /usr/share/beakerlib/beakerlib.sh

PACKAGE="checkpolicy"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm ${PACKAGE}
        TEST_FILE=`mktemp`
        TEST_DIR=`mktemp -d`
        rlRun "rpm -ql ${PACKAGE} | grep bin/checkmodule"
        rlRun "rpm -ql ${PACKAGE} | grep /usr/share/man/.*checkmodule"
    rlPhaseEnd

    rlPhaseStartTest
        rlRun "checkmodule >& ${TEST_FILE}" 1
        rlAssertGrep "unable to open policy.conf" ${TEST_FILE}
        rlRun "checkmodule -b >& ${TEST_FILE}" 1
        rlAssertGrep "Can't open 'policy':  No such file or directory" ${TEST_FILE}
        rlRun "checkmodule -V"
        rlRun "checkmodule -U 1>/dev/null" 1
        rlRun "rm -f policy.conf"
        for OPTION in "deny" "reject" "allow" ; do
            rlRun "checkmodule -U ${OPTION} >& ${TEST_FILE}" 1
            rlAssertGrep "unable to open policy.conf" ${TEST_FILE}
        done
        rlRun "rm -f ${TEST_FILE}"
        rlRun "touch ${TEST_FILE}"
        rlRun "rm -rf ${TEST_DIR}"
        rlRun "mkdir ${TEST_DIR}"
        rlRun "checkmodule ${TEST_FILE}" 1,2
        rlRun "checkmodule -b ${TEST_FILE}" 1
        rlRun "checkmodule ${TEST_DIR}" 1,2
        rlRun "checkmodule -b ${TEST_DIR}" 1
        rlRun "rm -f ${TEST_FILE}"
        rlRun "rm -rf ${TEST_DIR}"
        rlRun "checkmodule ${TEST_FILE}" 1
        rlRun "checkmodule -b ${TEST_FILE}" 1
        if rlIsRHEL 5 ; then
            rlRun "man checkmodule | col -b | grep -- -d"
            rlRun "checkmodule --help 2>&1 | grep -- -d"
        fi
        rlRun "man checkmodule | col -b | grep -- -h"
        rlRun "man checkmodule | col -b | grep -- -U"
        rlRun "checkmodule --help 2>&1 | grep -- -h"
        rlRun "checkmodule --help 2>&1 | grep -- -U"
    rlPhaseEnd

    rlPhaseStartTest
        for POLICY_KIND in minimum mls targeted ; do
            rlRun "checkmodule -M -m -b -o testmod.mod /etc/selinux/${POLICY_KIND}/policy/policy.* >& ${TEST_FILE}" 1
            rlRun "grep -i \"checkmodule.*-b and -m are incompatible with each other\" ${TEST_FILE}"
        done
    rlPhaseEnd

    rlPhaseStartTest
        INPUT_FILE="mypolicy.te"
        OUTPUT_FILE="mypolicy.output"
        rlRun "ls -l ${INPUT_FILE}"
        rlRun "checkmodule -m -o ${OUTPUT_FILE} ${INPUT_FILE}" 0
        rlRun "ls -l ${OUTPUT_FILE}" 0
        if checkmodule --help | grep -q " CIL " ; then
            rlRun "rm -f ${OUTPUT_FILE}"
            rlRun "checkmodule -m -C -o ${OUTPUT_FILE} ${INPUT_FILE}" 0
            rlRun "ls -l ${OUTPUT_FILE}" 0
        fi
    rlPhaseEnd

    rlPhaseStartCleanup
        rlRun "rm -rf ${TEST_FILE} ${TEST_DIR} ${OUTPUT_FILE}"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd

