#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/selinux-policy/Regression/rrdcached-service-and-related
#   Description: Basic test for rrdcached service
#   Author: Patrik Koncity <pkoncity@redhat.com>
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

PACKAGE="selinux-policy"
SERVICE_NAME="rrdcached"
SERVICE_PACKAGE="rrdtool"
PROCESS_NAME="rrdcached"
PROCESS_CONTEXT="rrdcached_t"
VAR_RUN_CONTEXT="rrdcached_var_run_t"
TMP_CONTEXT="rrdcached_tmp_t"

rlJournalStart
    rlPhaseStartSetup
        rlRun "rlImport 'selinux-policy/common'"
        rlAssertRpm $PACKAGE
        rlAssertRpm $SERVICE_PACKAGE
        rlSESetEnforce
        rlSEStatus
        rlSESetTimestamp
    rlPhaseEnd

    rlPhaseStartTest "bz#1726255"
        rlSEMatchPathCon "/usr/bin/rrdcached" "rrdcached_exec_t"
        rlSEMatchPathCon "/var/run/rrdcached.*" "rrdcached_var_run_t"
        rlSESearchRule "type_transition init_t rrdcached_exec_t : process ${PROCESS_CONTEXT}"
        rlSESearchRule "allow ${PROCESS_CONTEXT} self:capability { chown setgid setuid }"
        rlSESearchRule "allow ${PROCESS_CONTEXT} self:fifo_file { append create getattr ioctl link lock open read rename setattr unlink write } "
        rlSESearchRule "allow ${PROCESS_CONTEXT} self:unix_stream_socket { accept append bind connect create getattr getopt ioctl listen lock read setattr setopt shutdown write } "
        rlSESearchRule "allow ${PROCESS_CONTEXT} ${VAR_RUN_CONTEXT}:dir { add_name create getattr ioctl link lock open read remove_name rename reparent rmdir search setattr unlink write } "
        rlSESearchRule "allow ${PROCESS_CONTEXT} ${VAR_RUN_CONTEXT}:file { append create getattr ioctl link lock open read rename setattr unlink write }"
        rlSESearchRule "allow ${PROCESS_CONTEXT} ${VAR_RUN_CONTEXT}:lnk_file { append create getattr ioctl link lock read rename setattr unlink write }"
        rlSESearchRule "allow ${PROCESS_CONTEXT} var_t:dir { getattr open search }"
        rlSESearchRule "type_transition rrdcached_t var_run_t:dir rrdcached_var_run_t "
        rlSESearchRule "type_transition rrdcached_t var_run_t:file rrdcached_var_run_t "
        rlSESearchRule "type_transition rrdcached_t var_run_t:lnk_file rrdcached_var_run_t "
        rlSESearchRule "allow ${PROCESS_CONTEXT} ${TMP_CONTEXT}:dir { add_name create getattr ioctl link lock open read remove_name rename reparent rmdir search setattr unlink write }"
        rlSESearchRule "allow ${PROCESS_CONTEXT} ${TMP_CONTEXT}:file { append create getattr ioctl link lock open read rename setattr unlink write }"
        rlSESearchRule "allow ${PROCESS_CONTEXT} ${TMP_CONTEXT}:sock_file { append create getattr ioctl link lock open read rename setattr unlink write }"
        rlSESearchRule "allow ${PROCESS_CONTEXT} tmp_t:dir { add_name getattr ioctl lock open read remove_name search write }"
        rlSESearchRule "type_transition rrdcached_t tmp_t:dir ${TMP_CONTEXT} "
        rlSESearchRule "type_transition rrdcached_t tmp_t:file ${TMP_CONTEXT} "
        rlSESearchRule "type_transition rrdcached_t tmp_t:sock_file ${TMP_CONTEXT} "
        rlSESearchRule "typeattribute ${PROCESS_CONTEXT} nsswitch_domain"
        rlSESearchRule "typeattribute ${PROCESS_CONTEXT} netlabel_peer_type"
        rlSESearchRule "allow ${PROCESS_CONTEXT} privfd:fd use "
        rlSESearchRule "allow ${PROCESS_CONTEXT} etc_t:dir { getattr ioctl lock open read search }"
        rlSESearchRule "allow ${PROCESS_CONTEXT} etc_t:file { getattr ioctl lock open read }"
        rlSESearchRule "allow ${PROCESS_CONTEXT} etc_t:lnk_file { getattr read }"
        rlSESearchRule "allow ${PROCESS_CONTEXT} etc_runtime_t:file { getattr ioctl lock open read }"
        rlSESearchRule "allow ${PROCESS_CONTEXT} etc_runtime_t:lnk_file { getattr read }"
        rlSESearchRule "typeattribute ${PROCESS_CONTEXT} syslog_client_type"
    rlPhaseEnd

    rlPhaseStartTest "real scenario"
        rlSEService - ${SERVICE_NAME} ${PROCESS_NAME} ${PROCESS_CONTEXT} "start status" 2
        rlRun "restorecon -Rv /run /var"
        rlSEService - ${SERVICE_NAME} ${PROCESS_NAME} ${PROCESS_CONTEXT} "restart status stop status" 2
    rlPhaseEnd

    # TODO: add test scenario for rrdcached.socket

    rlPhaseStartCleanup
        sleep 2
        rlSECheckAVC
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd

