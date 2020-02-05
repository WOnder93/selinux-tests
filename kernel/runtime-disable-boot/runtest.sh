#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2014 Red Hat, Inc.
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

# Include Beaker environment
. /usr/bin/rhts-environment.sh || exit 1
. /usr/share/beakerlib/beakerlib.sh || exit 1

rlJournalStart
if [ $REBOOTCOUNT -lt 1 ]; then
    rlPhaseStartSetup
        rlFileBackup /etc/selinux/config

        rlRun "sed -iE 's/^\s*SELINUX\s*=\s*\w\+\s*$/SELINUX=disabled/g' /etc/selinux/config" 0 \
            "Disable SELinux in config"
        rhts-reboot
fi
if [ $REBOOTCOUNT -le 10 ]; then
    rlPhaseEnd

    rlPhaseStartTest "Reboot #$REBOOTCOUNT"
        rlAssertNotGrep "selinux=0" /proc/cmdline
        rlRun "! selinuxenabled"
        rlRun "dmesg | grep -q 'SELinux:  Disabled at runtime.'"
        rhts-reboot
fi
    rlPhaseEnd

    rlPhaseStartCleanup
        rlFileRestore
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd

