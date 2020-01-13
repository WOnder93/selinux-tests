#!/bin/bash

# This is a test file

# Include rhts environment
. /usr/bin/rhts-environment.sh
. /usr/share/beakerlib/beakerlib.sh

list_booleans() {
  semanage boolean -l | sort
}
rlIsRHEL 5 && {
  list_booleans() {
    paste <(getsebool ${1:--a} | sort) <(seinfo -b$1 -x $__INTERNAL_POLICY_FILE 2>/dev/null | sed -r '/^\S/d;/^\s*$/d;s/\<[Ff][Aa][Ll][Ss][Ee]\>/off/;s/\<[Tt][Rr][Uu][Ee]\>/on/' | sort) | sed -r 's/^(\S+).*\<(on|off)\>.*\<(on|off)\>.*/\1 (\2,\3)/;s/on,/on   ,/;s/off,/off  ,/;s/,on/,   on/;s/,off/,  off/'
  }
}

rlJournalStart
    rlPhaseStartSetup
        rlRun "rlImport selinux-policy/common"
    rlPhaseEnd

    rlPhaseStartTest "rlSEBoolean test"
        if ! selinuxenabled
        then
            rlLogWarning "SELinux disabled: test was not run" "WARN"
        else
            rlRun 'rlSEBooleanRestore a-boolean' 1-255 "rlSEBooleanRestore should fail when no rlSEBoolean functions were run"
            rlRun 'rlSEBooleanOn' 1-255 "rlSEBooleanOn should fail when no boolean is given"
            rlRun 'rlSEBooleanOff' 1-255 "rlSEBooleanOff should fail when no boolean is given"
            rlRun 'rlSEBooleanOn i_do_not_exist' 1-255 "rlSEBooleanOn should fail for non-existent boolean"
            rlRun 'rlSEBooleanOff i_do_not_exist' 1-255 "rlSEBooleanOff should fail for non-existent boolean"
            rlRun 'rlSEBooleanOn -P' 1-255 "rlSEBooleanOn -P should fail when no boolean is given"
            rlRun 'rlSEBooleanOff -P' 1-255 "rlSEBooleanOff -P should fail when no boolean is given"
            rlRun 'rlSEBooleanOn -P i_do_not_exist' 1-255 "rlSEBooleanOn -P should fail for non-existent boolean"
            rlRun 'rlSEBooleanOff -P i_do_not_exist' 1-255 "rlSEBooleanOff -P should fail for non-existent boolean"

            BOOL=( $(getsebool -a | grep ftp -m 4 | cut -d ' ' -f 1 | tr '\n' ' ') )
            tmp="$(list_booleans | grep ftp)"
            booleans_cleanup=''
            booleans_cleanupP=''
            for bool in ${BOOL[@]}; do
              [[ "$(echo "$tmp" | grep $bool)" =~ $(echo '(\S+)\)') ]] && booleans_cleanupP+="$bool=${BASH_REMATCH[1]} "
              [[ "$(echo "$tmp" | grep $bool)" =~ $(echo '\((\S+)') ]] && booleans_cleanup+="$bool=${BASH_REMATCH[1]} "
            done

            #Set initial state of booleans (all combinations - 00 01 10 11)
            rlRun "setsebool -P ${BOOL[0]}=off ${BOOL[1]}=on ${BOOL[2]}=off ${BOOL[3]}=on"
            rlRun "setsebool ${BOOL[1]}=off ${BOOL[2]}=on"

            # Change the booleans using rlSEBooleanOn/Off which includes backup
            rlRun "rlSEBooleanOn -P ${BOOL[0]} ${BOOL[2]}"
            rlRun "rlSEBooleanOff -P ${BOOL[1]} ${BOOL[3]}"
            rlRun "rlSEBooleanOn ${BOOL[1]} ${BOOL[2]}"
            rlRun "rlSEBooleanOff ${BOOL[0]} ${BOOL[3]}"

            # Check the correct values were set
            tmp="$(list_booleans)"
            echo "$tmp" | grep "\<${BOOL[0]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[0]}\>' | grep '(off  ,   on)'"
            echo "$tmp" | grep "\<${BOOL[1]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[1]}\>' | grep '(on   ,  off)'"
            echo "$tmp" | grep "\<${BOOL[2]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[2]}\>' | grep '(on   ,   on)'"
            echo "$tmp" | grep "\<${BOOL[3]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[3]}\>' | grep '(off  ,  off)'"

            rlRun "rlSEBooleanRestore"

            # Check the values was restored correctly
            tmp="$(list_booleans)"
            echo "$tmp" | grep "\<${BOOL[0]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[0]}\>' | grep '(off  ,  off)'"
            echo "$tmp" | grep "\<${BOOL[1]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[1]}\>' | grep '(off  ,   on)'"
            echo "$tmp" | grep "\<${BOOL[2]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[2]}\>' | grep '(on   ,  off)'"
            echo "$tmp" | grep "\<${BOOL[3]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[3]}\>' | grep '(on   ,   on)'"

            # Backup should fail because there already is a backup file
            rlRun "rlSEBooleanBackup" 33
            rlRun "rm -f $BEAKERLIB_DIR/sebooleans"
            
            # Backup all the booleans
            rlRun "rlSEBooleanBackup"

            # Change them using setsebool
            rlRun "setsebool ${BOOL[0]}=on ${BOOL[1]}=on ${BOOL[2]}=off ${BOOL[3]}=off"

            tmp="$(list_booleans)"
            echo "$tmp" | grep "\<${BOOL[0]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[0]}\>' | grep '(on   ,  off)'"
            echo "$tmp" | grep "\<${BOOL[1]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[1]}\>' | grep '(on   ,   on)'"
            echo "$tmp" | grep "\<${BOOL[2]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[2]}\>' | grep '(off  ,  off)'"
            echo "$tmp" | grep "\<${BOOL[3]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[3]}\>' | grep '(off  ,   on)'"

            # Restore only two of them
            rlRun "rlSEBooleanRestore ${BOOL[0]} ${BOOL[1]}"

            # Check only the two were restored
            tmp="$(list_booleans)"
            echo "$tmp" | grep "\<${BOOL[0]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[0]}\>' | grep '(off  ,  off)'"
            echo "$tmp" | grep "\<${BOOL[1]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[1]}\>' | grep '(off  ,   on)'"
            echo "$tmp" | grep "\<${BOOL[2]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[2]}\>' | grep '(off  ,  off)'"
            echo "$tmp" | grep "\<${BOOL[3]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[3]}\>' | grep '(off  ,   on)'"

            # Change two bools using rlSEBooleanOn/Off to make sure it won't rewrite the backup
            rlRun "rlSEBooleanOn -P ${BOOL[0]}"
            rlRun "rlSEBooleanOff -P ${BOOL[1]}"

            # Restore all by listing them
            rlRun "rlSEBooleanRestore ${BOOL[0]} ${BOOL[1]} ${BOOL[2]} ${BOOL[3]}"

            # ..and check it all is restored correctly
            tmp="$(list_booleans)"
            echo "$tmp" | grep "\<${BOOL[0]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[0]}\>' | grep '(off  ,  off)'"
            echo "$tmp" | grep "\<${BOOL[1]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[1]}\>' | grep '(off  ,   on)'"
            echo "$tmp" | grep "\<${BOOL[2]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[2]}\>' | grep '(on   ,  off)'"
            echo "$tmp" | grep "\<${BOOL[3]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[3]}\>' | grep '(on   ,   on)'"

            rlRun "rm -f $BEAKERLIB_DIR/sebooleans"
            # Now backup only two booleans
            # Change them all
            rlRun "rlSEBooleanOn -P ${BOOL[0]}"
            rlRun "rlSEBooleanOff -P ${BOOL[1]}"
            rlRun "setsebool -P ${BOOL[2]}=on ${BOOL[3]}=off"
            rlRun "setsebool ${BOOL[2]}=off ${BOOL[3]}=on"

            # Check they are changed
            tmp="$(list_booleans)"
            echo "$tmp" | grep "\<${BOOL[0]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[0]}\>' | grep '(on   ,   on)'"
            echo "$tmp" | grep "\<${BOOL[1]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[1]}\>' | grep '(off  ,  off)'"
            echo "$tmp" | grep "\<${BOOL[2]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[2]}\>' | grep '(off  ,   on)'"
            echo "$tmp" | grep "\<${BOOL[3]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[3]}\>' | grep '(on   ,  off)'"

            # Restoring not backed up booleans should fail
            rlRun "rlSEBooleanRestore ${BOOL[2]} ${BOOL[3]}" 1-255

            # And this should restore only the backed up booleans
            rlRun "rlSEBooleanRestore"

            # Check only backed up booleans were restored
            tmp="$(list_booleans)"
            echo "$tmp" | grep "\<${BOOL[0]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[0]}\>' | grep '(off  ,  off)'"
            echo "$tmp" | grep "\<${BOOL[1]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[1]}\>' | grep '(off  ,   on)'"
            echo "$tmp" | grep "\<${BOOL[2]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[2]}\>' | grep '(off  ,   on)'"
            echo "$tmp" | grep "\<${BOOL[3]}\>"
            rlRun "echo \"\$tmp\" | grep '\<${BOOL[3]}\>' | grep '(on   ,  off)'"

            # Cleanup - set all the booleans back to off-off
            rlRun "setsebool -P $booleans_cleanupP"
            rlRun "setsebool $booleans_cleanup"
        fi
    rlPhaseEnd

    rlPhaseStartTest "rlSESearchRule test"
        rlSESearchRule "allow winbind_t port_t : tcp_socket name_connect"  
        rlSESearchRule "allow unconfined_t smbcontrol_t : fd use targeted" 0
        rlSESearchRule "allow unconfined_t smbcontrol_t : fd use mls" 1
        rlSESearchRule "allow ftpd_t public_content_rw_t : dir { create write }"
        rlSESearchRule "allow ftpd_t public_content_rw_t : dir { create write } [ rsync_client ]" 1
        rlSESearchRule "allow ftpd_t public_content_rw_t : dir { create write } [ allow_ftpd_anon_write ]" 0
    rlPhaseEnd

    if rlIsRHEL '>=8'; then
        cache_echo() {
            echo CACHED:
            echo "$1"
            echo SESEARCH:
            echo "$2"
        }
        rlPhaseStartTest "sesearch cache demo"
            rlRun "cached=\$(__INTERNAL_rlSEcache_sesearch --allow -s winbind_t -t port_t -c tcp_socket)"
            rlRun "real=\$(sesearch --allow -s winbind_t -t port_t -c tcp_socket)"
            cache_echo "$cached" "$real"
            rlRun "cached=\$(__INTERNAL_rlSEcache_sesearch --allow -s nsswitch_domain -t port_type -c tcp_socket)"
            rlRun "real=\$(sesearch --allow -s nsswitch_domain -t port_type -c tcp_socket -ds -dt)"
            cache_echo "$cached" "$real"
            rlRun "cached=\$(__INTERNAL_rlSEcache_sesearch --type_trans -s xguest_t -t httpd_sys_ra_content_t -c process)"
            rlRun "real=\$(sesearch --type_trans -s xguest_t -t httpd_sys_ra_content_t -c process)"
            cache_echo "$cached" "$real"
            rlRun "cached=\$(__INTERNAL_rlSEcache_sesearch --dontaudit -s abrt_helper_t -t domain -c rose_socket)"
            rlRun "real=\$(sesearch --dontaudit -s abrt_helper_t -t domain -c rose_socket)"
            cache_echo "$cached" "$real"
        rlPhaseEnd
    fi

    rlPhaseStartTest "timestamps test"
        rlSESetTimestamp
        sleep 2
        rlSESetTimestamp mine
        sleep 2
        rlSECheckAVC
        rlSECheckAVC mine
    rlPhaseEnd

    rlPhaseStartCleanup
    rlPhaseEnd
    rlJournalPrintText
rlJournalEnd

