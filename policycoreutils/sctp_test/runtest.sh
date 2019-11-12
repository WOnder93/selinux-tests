#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /selinux/policycoreutils/sctp_test
#   Description: Is SCTP supported by "semanage port"?
#   Author: vmojzis <vmojzis@redhat.com>
#   Simulates a use case where a user wants to confine a client-server application communicating over SCTP
#   Bug summary: semanage port does not support SCTP protocol
#   Bugzilla link: https://bugzilla.redhat.com/show_bug.cgi?id=1563742
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
PORT_TYPE="sctp_port_t"
CLIENT_PORT="1025"
SERVER_PORT="1026"

# This test simulates a use case where a user wants to confine a client-server
# application communicating over SCTP protocol
rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm $PACKAGE
        # make sure the right version of kernel[-rt]-modules-extra is installed
        rlRun "dnf install -y kernel-modules-extra-$(uname -r)" 0-255
        rlRun "dnf install -y kernel-rt-modules-extra-$(uname -r)" 0-255
        rlRun "modprobe sctp" 0 "Enabling SCTP kernel module"
        # A custom policy module is used to introduce a new port type, domain type
        # for the application and an executable file type for the application
        # executable as well as a minimal set of allow rules for sctp_test to work
        # properly.
        rlRun "semodule -i userapp.cil" 0 "Loading custom policy module"
        rlRun "chcon -t userapp_exec_t `which sctp_test`" 0 "Change file context of sctp_test"
        OUTPUT_FILE=`mktemp`
        rlRun "setenforce 1"
        rlRun "sestatus"
    rlPhaseEnd

    rlPhaseStartTest
        rlRun "semanage port -a -t ${PORT_TYPE} -p sctp ${SERVER_PORT}" 0
        rlRun "semanage port -a -t ${PORT_TYPE} -p sctp ${CLIENT_PORT}" 0
        rlRun "semanage port -l 2>&1 > ${OUTPUT_FILE}" 0
        rlRun "grep -E \"${PORT_TYPE}.+sctp.+${CLIENT_PORT}\" ${OUTPUT_FILE}"
        if [ $? -ne 0 ]; then cat ${OUTPUT_FILE}; fi
        rlRun "semanage port -l -C 2>&1 > ${OUTPUT_FILE}" 0
        rlRun "grep -E \"${PORT_TYPE}.+sctp.+${SERVER_PORT}\" ${OUTPUT_FILE}"
        if [ $? -ne 0 ]; then cat ${OUTPUT_FILE}; fi
        rlRun "sctp_test -H localhost -P ${SERVER_PORT} -l 2>&1 > ${OUTPUT_FILE} &" 0
        rlRun "sctp_test -H localhost -P ${CLIENT_PORT} -h localhost -p ${SERVER_PORT} -s" 0
        rlRun "grep 'recvmsg' ${OUTPUT_FILE} -i" 0
        if [ $? -ne 0 ]; then cat ${OUTPUT_FILE}; fi
    rlPhaseEnd

    rlPhaseStartCleanup
        rlRun "rm -f ${OUTPUT_FILE}"
        rlRun "killall sctp_test"
        rlRun "semanage port -D"
        rlRun "semodule -r userapp"
        rlRun "restorecon -Rv `which sctp_test`"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
