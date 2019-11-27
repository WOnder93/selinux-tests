#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /selinux/policycoreutils/restorecond_pointer_abuse
#   Description:
#      This test creates mislabeled files and runs restorecond repeatedly to test
#      for an issue caused by overwriting program variable with memory address.
#      The issue caused restorecond to write status messages (that appeared
#      as "blob data" because of \r character) to journal.
#
#      Since the memory address mentioned above is effectively random data,
#      this test may result in SUCESS even if the issue being tested is present!
#
#   Author: vmojzis <vmojzis@redhat.com>
#   Bug summary: restorecond flooding logs with blob data messages
#   Bugzilla link: https://bugzilla.redhat.com/show_bug.cgi?id=1626468
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

# Requires /usr/sbin/restorecond, /usr/bin/chcon, /usr/sbin/sestatus, /usr/bin/systemctl, /usr/bin/journalctl
rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm $PACKAGE
        # backup restorecond configuration file
        rlRun "rlFileBackup /etc/selinux/restorecond.conf" 0
        rlRun "echo '/usr/*' > /etc/selinux/restorecond.conf" 0-255
        OUTPUT_FILE=`mktemp`
        rlRun "setenforce 1"
        rlRun "sestatus"
        START_DATE_TIME=`date "+%Y-%m-%d %T"`
    rlPhaseEnd

    rlPhaseStartTest
        # 
        for i in {1..15}
        do
            # create misslabeled files
            for folder in  share games tmp
            do
                rlRun "touch /usr/$folder/$i"
                rlRun "chcon -t unlabeled_t /usr/$folder/$i"
            done
            rlRun "systemctl restart restorecond" 0
            rlRun "systemctl status restorecond" 0
            rlRun "journalctl -S '$START_DATE_TIME' -u restorecond 2>&1 > ${OUTPUT_FILE}" 0
            rlRun "grep -E \"blob data\" ${OUTPUT_FILE}" 1
            if [ $? -ne 1 ]; then cat ${OUTPUT_FILE}; fi
            sleep 3
            # cleanup
            for folder in share games tmp
            do
                rlRun "rm -f /usr/$folder/$i"
            done
        done
    rlPhaseEnd

    rlPhaseStartCleanup
        rlRun "rlFileRestore" 0
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
