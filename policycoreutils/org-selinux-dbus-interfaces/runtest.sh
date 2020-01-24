#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/policycoreutils/Sanity/org-selinux-dbus-interfaces
#   Description: Do the D-bus interfaces/methods of /org/selinux/object work as expected?
#   Author: Milos Malik <mmalik@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2017 Red Hat, Inc.
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

PACKAGE="policycoreutils"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm ${PACKAGE}
        # In past, org.selinux dbus interface was shipped in policycoreutils-gui
        rlRun "rpm -q policycoreutils-dbus || rpm -q policycoreutils-gui" 0
        rlFileBackup /etc/selinux/config
        rlRun "gdbus introspect --system -d org.selinux -o /"
        rlRun "gdbus introspect --system -d org.selinux -o /org"
        rlRun "gdbus introspect --system -d org.selinux -o /org/selinux"
        rlRun "gdbus introspect --system -d org.selinux -o /org/selinux/object"
        rlRun "ps -efZ | grep -v grep | grep ':semanage_t:.*selinux_server'"
    rlPhaseEnd

    rlPhaseStartTest "org.selinux.semodule_list"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.semodule_list"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.semodule_list int64:0" 1
    rlPhaseEnd

    rlPhaseStartTest "org.selinux.customized"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.customized"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.customized int64:0" 1
    rlPhaseEnd

    rlPhaseStartTest "org.selinux.setenforce"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.setenforce" 1
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.setenforce int64:0"
        rlRun "getenforce | grep -i Permissive"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.setenforce int64:0"
        rlRun "getenforce | grep -i Permissive"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.setenforce int64:1"
        rlRun "getenforce | grep -i Enforcing"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.setenforce int64:1"
        rlRun "getenforce | grep -i Enforcing"
    rlPhaseEnd

    rlPhaseStartTest "org.selinux.relabel_on_boot"
        rlLog "bz#1415988 + bz#1754873"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.relabel_on_boot" 1
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.relabel_on_boot int64:1"
        rlRun "ls -Z /.autorelabel"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.relabel_on_boot int64:1"
        rlRun "ls -Z /.autorelabel"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.relabel_on_boot int64:0"
        rlRun "ls -Z /.autorelabel" 2
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.relabel_on_boot int64:0"
        rlRun "ls -Z /.autorelabel" 2
    rlPhaseEnd

    rlPhaseStartTest "org.selinux.restorecon"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.restorecon" 1
        # TODO restorecon(in  s path);
    rlPhaseEnd

    rlPhaseStartTest "org.selinux.semanage"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.semanage" 1
        # TODO semanage(in  s buf);
    rlPhaseEnd

    rlPhaseStartTest "org.selinux.change_default_policy"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.change_default_policy" 1
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.change_default_policy string:minimum"
        rlRun "grep SELINUXTYPE=minimum /etc/selinux/config"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.change_default_policy string:mls"
        rlRun "grep SELINUXTYPE=mls /etc/selinux/config"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.change_default_policy string:targeted"
        rlRun "grep SELINUXTYPE=targeted /etc/selinux/config"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.change_default_policy string:xyz" 1
    rlPhaseEnd

    rlPhaseStartTest "org.selinux.change_default_mode"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.change_default_mode" 1
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.change_default_mode string:disabled"
        rlRun "grep SELINUX=disabled /etc/selinux/config"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.change_default_mode string:permissive"
        rlRun "grep SELINUX=permissive /etc/selinux/config"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.change_default_mode string:enforcing"
        rlRun "grep SELINUX=enforcing /etc/selinux/config"
        rlRun "dbus-send --system --print-reply --dest=org.selinux /org/selinux/object org.selinux.change_default_mode string:xyz" 1
    rlPhaseEnd

    rlPhaseStartCleanup
        rlFileRestore
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd

