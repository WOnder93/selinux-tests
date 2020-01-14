#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/selinux-policy/Sanity/serge-testsuite
#   Description: functional test suite for the LSM-based SELinux security module
#   Author: Milos Malik <mmalik@redhat.com>
#
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

PACKAGE="selinux-policy"

# Default commit to checkout from the repo.
# This should be updated as needed after verifying that the new version
# doesn't break testing and after applying all necessary tweaks in the TC.
# Run with GIT_BRANCH=master to run the latest upstream version.
DEFAULT_COMMIT="7fd02b152f9f081298c676688a382d905aafb9fc"
# Default pull requests to merge before running the test.
# If non-empty, then after checking out GIT_BRANCH the listed upstream pull
# requests (by number) are merged, creating a new temporary local branch.
DEFAULT_PULLS=""
# Default SELinux Patchwork series to apply before running the test.
DEFAULT_PATCHES=""

# Optional test parameter - location of testuite git.
GIT_URL=${GIT_URL:-"git://github.com/SELinuxProject/selinux-testsuite"}

# Optional test parameter - timeout for detecting lost packets
NETWORK_TIMEOUT=${NETWORK_TIMEOUT:-4}

# Optional test parameter - branch containing tests.
if [ -z "$GIT_BRANCH" ]; then
    GIT_BRANCH="$DEFAULT_COMMIT"
    # Use default cherries only if branch is default and they are not overriden
    GIT_PULLS="${GIT_PULLS:-"$DEFAULT_PULLS"}"
    GIT_PATCHES="${GIT_PATCHES:-"$DEFAULT_PATCHES"}"
fi

# DISTRO unset needed for policy devel Makefile... (Beaker sets it to "RHEL-...")
TS_ENV="env -u ARCH -u DISTRO LANG=C"

# Check if pipefail is enabled to restore original setting.
# See: https://unix.stackexchange.com/a/73180
if false | true; then
    PIPEFAIL_ENABLE="set -o pipefail"
    PIPEFAIL_DISABLE="set +o pipefail"
else
    PIPEFAIL_ENABLE=""
    PIPEFAIL_DISABLE=""
fi

if rlIsRHEL 5 ; then
    # On RHEL-5 sort -V doesn't work, so just pretend we have the oldest kernel
    function kver_ge() { false; }
    function kver_lt() { true;  }
    function kver_le() { true;  }
    function kver_gt() { false; }
else
    function version_le() {
        { echo "$1"; echo "$2"; } | sort -V | tail -n 1 | grep -qx "$2"
    }

    function kver_ge() { version_le "$1" "$(uname -r)"; }
    function kver_lt() { ! kver_ge "$1"; }
    function kver_le() { version_le "$(uname -r)" "$1"; }
    function kver_gt() { ! kver_le "$1"; }
fi

function installDepsYum() {
    local yum="$1"; shift

    if "$yum" --help | grep -q -- --skip-broken; then
        "$yum" install -y --skip-broken $*
    else
        for req in $*; do
            if ! rpm -q --quiet --whatprovides "$req"; then
                "$yum" install -y "$req" || true
            fi
        done
    fi
}

function installDeps() {
    if type yum >/dev/null; then
        installDepsYum yum "$@"
    elif type dnf >/dev/null; then
        installDepsYum dnf "$@"
    fi
}

function boolGet() {
    getsebool "$1" | cut -d ' ' -f 3
}
function boolSet() {
    getsebool -a | cut -d ' ' -f 1 | grep "^$1\$" || return 0
    setsebool "$1" "$2" || return 1
    [ "$(boolGet "$1")" == "$2" ]
}


rlJournalStart
    rlPhaseStartSetup "Install"
        # We need to install the kernel-* packages by ourselves, since we need
        # the same versions as the running kernel. And since we already need a
        # reliable package install function, let's just install all the
        # dependencies here. Thus we don't need to maintain duplicate lists of
        # package requirements in many places (RH repo, Fedora kernel dist-git,
        # CKI).
        PKG_SUFFIX=""
        KERNEL_VERSION="$(uname -r)"
        PKG_VERSION="${KERNEL_VERSION%+debug}"
        if [ "$PKG_VERSION" != "$KERNEL_VERSION" ]; then
            rlLog "Detected debug kernel running."
            PKG_SUFFIX="-debug"
        fi

        REQUIRES="
            kernel$PKG_SUFFIX-modules-extra-$PKG_VERSION
            kernel-rt$PKG_SUFFIX-modules-extra-$PKG_VERSION
            kernel$PKG_SUFFIX-devel-$PKG_VERSION
            kernel-rt$PKG_SUFFIX-devel-$PKG_VERSION
            /usr/bin/unbuffer
            attr
            audit
            checkpolicy
            curl
            elfutils-libelf-devel
            expect
            gcc
            git
            grep
            ipsec-tools
            iptables
            keyutils-libs-devel
            libbpf-devel
            libibverbs-devel
            libselinux
            libselinux-devel
            libselinux-utils
            libsemanage
            libsepol-devel
            lksctp-tools-devel
            mktemp
            nc
            netlabel_tools
            net-tools
            nmap-ncat
            perl-Test
            perl-Test-Harness
            perl-Test-Simple
            platform-python
            policycoreutils
            policycoreutils-devel
            policycoreutils-python
            python3
            python2-lxml
            python3-lxml
            rdma-core-devel
            selinux-policy
            selinux-policy-devel
            setools-console
            which
        "
        rlRun "installDeps \$REQUIRES" 0 "Install requires"
    rlPhaseEnd

    rlPhaseStartSetup
        rlAssertRpm ${PACKAGE}
        rlAssertRpm audit
        rlFileBackup /etc/selinux/semanage.conf
        # running the testsuite in /tmp causes permission denied messages
        # rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        # rlRun "pushd $TmpDir"

        if ! rlIsRHEL 5 ; then
            # version_le() sanity check:
            rlRun "version_le 4.10 4.10"
            rlRun "version_le 4.10 4.10.0"
            rlRun "version_le 4.10 4.10.1"
            rlRun "! version_le 4.10 4.9"
            rlRun "! version_le 4.10.0 4.10"
        fi

        if [ -d /sys/fs/selinux ]; then
            selinuxfs=/sys/fs/selinux
        else
            selinuxfs=/selinux
        fi

        # test turns this boolean off
        rlRun "BACKUP_allow_domain_fd_use=\$(boolGet allow_domain_fd_use)"
        rlRun "BACKUP_domain_can_mmap_files=\$(boolGet domain_can_mmap_files)"
        # test expects that domains cannot map files by default
        rlRun "boolSet domain_can_mmap_files off"

        rlRun "setenforce 1"
        rlRun "sestatus"
        if grep 'expand-check' /etc/selinux/semanage.conf; then
            rlRun "sed -i 's/^expand-check[ ]*=.*$/expand-check = 0/' /etc/selinux/semanage.conf"
        else
            rlRun "echo 'expand-check = 0' >>/etc/selinux/semanage.conf"
        fi
        if [ ! -d selinux-testsuite ] && rlRun "git clone $GIT_URL" 0; then
            rlRun "pushd selinux-testsuite"
            rlRun "git checkout $GIT_BRANCH" 0
            for _ in $GIT_PULLS $GIT_PATCHES; do
                rlRun "git config --global user.email nobody@redhat.com"
                rlRun "git config --global user.name 'Nemo Nobody'"
                rlRun "git checkout -b testing-cherry-picks" 0
                break
            done
            for pull in $GIT_PULLS; do
                ref="refs/pull/$pull/head"
                if ! rlRun "git fetch origin $ref:$ref" 0; then
                    rlRun "git checkout $GIT_BRANCH" 0
                    rlLogWarning "PR merge failed, falling back to GIT_BRANCH"
                    break
                fi
                if ! rlRun "git merge --no-edit $ref" 0; then
                    rlRun "git merge --abort" 0
                    rlRun "git checkout $GIT_BRANCH" 0
                    rlLogWarning "PR merge failed, falling back to GIT_BRANCH"
                    break
                fi
            done
            $PIPEFAIL_ENABLE
            for pwseries in $GIT_PATCHES; do
                url="https://patchwork.kernel.org/series/$pwseries/mbox/"
                if ! rlRun "curl $url | git am -"; then
                    rlRun "git checkout $GIT_BRANCH" 0
                    rlLogWarning "Applying patch failed, falling back to GIT_BRANCH"
                    break
                fi
            done
            $PIPEFAIL_DISABLE
            rlRun "popd"
        fi

        if [ -d selinux-testsuite ]; then
            rlRun "pushd selinux-testsuite"

            # backup code before making tweaks
            rlFileBackup "."

            if [ "$VERBOSE" = "1" ]; then
                rlRun "sed -i 's/\(use Test::Harness;\)/\1 \$Test::Harness::verbose = TRUE;/' tests/runtests.pl" 0 \
                    "Enable verbose output"
            fi

            {
                echo "#ifndef IFF_NAPI"
                echo "#define IFF_NAPI 0x0010"
                echo "#endif"
                echo "#ifndef IFF_NAPI_FRAGS"
                echo "#define IFF_NAPI_FRAGS 0x0020"
                echo "#endif"
                echo "#ifndef IFF_NO_PI"
                echo "#define IFF_NO_PI 0x1000"
                echo "#endif"
            } | rlRun "tee -a tests/tun_tap/tun_common.h" 0 \
                "Harden tun_tap test against missing defs"

            exclude_tests=""
            for file in ./tests/nnp*/execnnp.c; do
                rlRun "sed -i 's/3.18/3.9/' $file" 0 \
                    "Fix up kernel version in nnp test"
            done
            if rlIsRHEL ; then
                rlRun "sed -i 's/4.20.17/4.18/' tests/Makefile" 0 \
                    "Fix up kernel version for sctp test"
                rlRun "sed -i 's/5.2/4.18.0-80.19/' tests/Makefile" 0 \
                    "Fix up kernel version for cgroupfs_label test"
                # CONFIG_KEYS_DH_COMPUTE not enabled on RHEL-8 :(
                exclude_tests+=" keys"
            fi
            if rlIsRHEL 5 ; then
                rlRun "sed -i '/unconfined_devpts_t/d' policy/test_policy.if" 0

                rlRun "sed -i 's/read_file_perms/r_file_perms/'  policy/*.te" 0
                rlRun "sed -i 's/mmap_file_perms/rx_file_perms/' policy/*.te" 0
                rlRun "sed -i 's/list_dir_perms/r_dir_perms/'    policy/*.te" 0
                rlRun "sed -i 's/ open / /'                      policy/*.te" 0

                rlRun "sed -i 's/^sysadm_bin_spec_domtrans_to/userdom_sysadm_bin_spec_domtrans_to/' policy/*.te" 0

                rlRun "sed -i 's/^corecmd_exec_bin(\(.*\))$/corecmd_exec_bin(\1)\ncorecmd_exec_sbin(\1)/' policy/*.te" 0
                rlRun "sed -i 's/^corecmd_bin_entry_type(\(.*\))$/corecmd_bin_entry_type(\1)\ncorecmd_sbin_entry_type(\1)/' policy/*.te" 0
                rlRun "sed -i 's/^userdom_search_user_home_dirs(\(.*\))$/userdom_search_user_home_dirs(user, \1)/' policy/*.te" 0
            fi
            if ! [ -x /usr/bin/python3 ]; then
                # to avoid error messages like runcon: ‘overlay/access’: No such file or directory
                rlRun "rpm -qa | grep python | sort"
                rlRun "sed -i 's/python3\$/python2/' tests/overlay/access" 0 \
                    "Fix up Python shebang in overlay test"
            fi

            rlRun "sed -i 's/tm\.tv_sec = [0-9]*;/tm.tv_sec = $NETWORK_TIMEOUT;/' ./tests/*/*.c" 0 \
                "Tweak timeout in networking tests" # 2 secs is too little for SCTP test

            if kver_lt "3.10.0-349"; then
                # c4684bbdac07 [security] selinux: Permit bounded transitions under NO_NEW_PRIVS or NOSUID
                # da74590f6501 [security] selinux: reject setexeccon() on MNT_NOSUID applications with -EACCES
                exclude_tests+=" nnp_nosuid"
            fi

            if kver_lt "3.10.0-693"; then
                # I don't know when exactly this test starts passing, so I'm just
                # disabling it for anything below the RHEL-7.4 kernel...
                exclude_tests+=" inet_socket"
            fi

            if kver_lt "3.10.0-875"; then
                rlLog "No xperms support => disable xperms testing"
                rlRun "sed -i '/TARGETS += test_ioctl_xperms\.te/d' policy/Makefile"
                rlRun "sed -i 's/\$kernver >= 30/\$kernver >= 999999/' tests/ioctl/test"
            fi
            # workaround for https://bugzilla.redhat.com/show_bug.cgi?id=1613056
            # (if running kernel version sorts inside the known-bug window, then
            # we need to apply the workaround)
            if kver_ge "3.10.0-875" && kver_lt "3.10.0-972"; then
                rlLog "Applying workaround for BZ 1613056..."
                rlRun "cat >>policy/test_ipc.te <<<'allow_map(ipcdomain, tmpfs_t, file)'"
                rlRun "cat >>policy/test_mmap.te <<<'allow_map(test_execmem_t, tmpfs_t, file)'"
                rlRun "cat >>policy/test_mmap.te <<<'allow_map(test_no_execmem_t, tmpfs_t, file)'"
            fi

            if rlIsRHEL || [ "$(rlGetPrimaryArch)" != x86_64 ]; then
                rlRun "sed -i '/SUBDIRS += bpf/d;/export CFLAGS += -DHAVE_BPF/d' tests/Makefile" 0 \
                    "Disable BPF tests on RHEL and non-x86_64 Fedora"
            fi

            # CKI mainline kernels don't ship with module build infrastructure
            # just yet. Also, RHEL-8 CKI kernel-devel programs are
            # cross-compiled badly for alt arches, so try executing one of them.
            if ! "/lib/modules/$(uname -r)/build/scripts/conmakehash" /dev/null &>/dev/null; then
                exclude_tests+=" module_load"
            fi

            if [ -n "$exclude_tests" ] ; then
                rlRun "sed -i '/^[^[:space:]]*:\(\| .*\)\$/i SUBDIRS:=\$(filter-out $exclude_tests, \$(SUBDIRS))' tests/Makefile" 0 \
                    "Exclude not applicable tests: $exclude_tests"
            fi

            if ! modprobe sctp 2>/dev/null; then
                script1='s/runcon -t test_sctp_socket_t/true/g'
                script2='s/runcon -t test_no_sctp_socket_t/false/g'
                rlRun "sed -i -e '$script1' -e '$script2' ./tests/extended_socket_class/test" 0 \
                    "No SCTP support => fix up extended_socket_class test"
            fi

            # on aarch64 and s390x the kernel support for Bluetooth is turned
            # off so we disable the Bluetooth socket tests there
            case "$(rlGetPrimaryArch)" in
                aarch64|s390x)
                    script1='s/runcon -t test_bluetooth_socket_t/true/g'
                    script2='s/runcon -t test_no_bluetooth_socket_t/false/g'
                    rlRun "sed -i -e '$script1' -e '$script2' ./tests/extended_socket_class/test" 0 \
                        "No Bluetooth support => fix up extended_socket_class test"
                    ;;
            esac

            # Initialize report.
            rlRun "echo 'Remote: $GIT_URL' >results.log" 0
            rlRun "echo 'Branch: $GIT_BRANCH' >>results.log" 0
            rlRun "echo 'Commit: $(git rev-parse $GIT_BRANCH)' >>results.log" 0
            rlRun "echo 'GH PRs: ${GIT_PULLS:-"(none)"}' >>results.log" 0
            rlRun "echo 'Series: ${GIT_PATCHES:-"(none)"}' >>results.log" 0
            rlRun "echo 'Kernel: $(uname -r)' >>results.log" 0
            rlRun "echo 'Policy: $(rpm -q selinux-policy)' >>results.log" 0
            rlRun "echo '        $(rpm -q checkpolicy)' >>results.log" 0
            rlRun "echo '        $(rpm -q libselinux)' >>results.log" 0
            rlRun "echo '        $(rpm -q libsemanage)' >>results.log" 0
            rlRun "echo '        $(rpm -q libsepol)' >>results.log" 0
            rlRun "echo '        $(rpm -q policycoreutils)' >>results.log" 0
            rlRun "echo '' >>results.log" 0

            rlRun "popd"
        fi
        rlRun "AUDIT_FILE=\"\$(mktemp)\""
        rlRun "auditctl -w \"\$AUDIT_FILE\" -p w" 0 \
            "Enable creation of PATH audit records"
    rlPhaseEnd

    rlPhaseStartTest
        if [ -d selinux-testsuite ]; then
            rlRun "pushd selinux-testsuite"
            rlRun "$TS_ENV make SELINUXFS=$selinuxfs" 0
            rlRun "cat results.log" 0
            $PIPEFAIL_ENABLE
            rlRun "$TS_ENV unbuffer make -s test SELINUXFS=$selinuxfs 2>&1 | tee -a results.log" 0
            $PIPEFAIL_DISABLE
            rlRun "popd"
        else
            rlFail "GIT was unable to clone the testsuite repo"
        fi
    rlPhaseEnd

    rlPhaseStartCleanup
        rlRun "auditctl -W \"\$AUDIT_FILE\" -p w" 0 \
            "Remove rule for creation of PATH audit records"
        rlRun "rm -f \"\$AUDIT_FILE\""
        # rlSEBooleanRestore
        # rlSEBooleanRestore allow_domain_fd_use
        # none of above-mentioned commands is able to correctly restore the value in the boolean
        rlRun "boolSet domain_can_mmap_files $BACKUP_domain_can_mmap_files"
        rlRun "boolSet allow_domain_fd_use $BACKUP_allow_domain_fd_use"

        if [ -d selinux-testsuite ]; then
            rlRun "pushd selinux-testsuite"
            # Submit report to beaker.
            rlFileSubmit "results.log" "selinux-testsuite.results.$(uname -r).txt"
            rlRun "$TS_ENV make -s clean SELINUXFS=$selinuxfs" 0-2
            rlRun "popd"
        fi
        rlRun "semodule -r test_policy" 0,1
        rlRun "sleep 5" 0
        rlRun "dmesg | grep -i \"rcu_sched detected stalls\"" 1
        rlFileRestore
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd

