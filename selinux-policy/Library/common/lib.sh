#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   lib.sh of /CoreOS/selinux-policy/Library/common
#   Description: Common library for selinux-policy component
#   Authors: Milos Malik <mmalik@redhat.com>
#            Michal Trunecka <mtruneck@redhat.com>
#            David Spurek <dspurek@redhat.com>
#            Jiri Jaburek <jjaburek@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2020 Red Hat, Inc. All rights reserved.
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
#   library-prefix = rlSE
#   library-version = 40
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

: <<'=cut'
=pod

=head1 NAME

selinux-policy/common - BeakerLib extension for managing SELinux

=cut

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Variables
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

: <<'=cut'
=pod

=head1 VARIABLES

=over

=item rlSE_CACHE_DIR

Used by sesearch caching for storing the ~90M cache file. Defaults to
a subdirectory under /var/tmp.

=back

=cut

rlSE_CACHE_DIR="${rlSE_CACHE_DIR:-$__INTERNAL_PERSISTENT_TMP/BEAKERLIB-rlSE}"

__INTERNAL_rlSE_CACHEFILE="$rlSE_CACHE_DIR/cache.db"
__INTERNAL_rlSE_SUMFILE="$rlSE_CACHE_DIR/cache.policy-checksum"


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Functions
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

true <<'=cut'
=pod

=head1 FUNCTIONS

=head2 rlSESearchRule

Searches for given SELinux rule. Checks if the rule is in the boolean if given. Checks if the rule is in the current policy, if not given other (e.g. mls).

Usage:
    rlSESearchRule "RULE" [EXP_RESULT] [DESC]
    rlSESearchRule "RULE [[BOOLEAN]] [POLICY]" [EXP_RESULT] [DESC]

=over

=item EXP_RESULT

Normally expected is '0' but you can the negation using '1'.

=item DESC



=back

Examples:
    rlSESearchRule "dontaudit smbd_t etc_conf_t:dir { getattr open }"
    rlSESearchRule "dontaudit smbd_t etc_conf_t:dir { getattr open } []"
    rlSESearchRule "allow ftpd_t public_content_rw_t: dir write [ allow_ftpd_anon_write ]"
    rlSESearchRule "allow ftpd_t public_content_rw_t: dir write [ allow_ftpd_anon_write ] mls"
    rlSESearchRule "typeattribute httpd_sys_script_exec_t file_type, exec_type"
    rlSESearchRule "type_transition initrc_t kdumpgui_exec_t : process kdumpgui_t"
    rlSESearchRule "type_transition authconfig_t etc_t : file bootloader_etc_t zipl.conf"
    rlSESearchRule "type_transition authconfig_t etc_t : file bootloader_etc_t [] zipl.conf mls"

=cut

rlSELogVar() {
  [[ -n "$DEBUG" ]] && {
    echo -n 'eval '
    while [[ -n "$1" ]]; do
      echo -n "rlLogDebug \"\$FUNCNAME(): \$(set | grep -P '^$1=')\";"
      shift
    done
  }
}

rlSESearchRule() {

  if [ -e /var/run/nosesearch ]; then
     echo "rlSESearchRule disabled by /var/run/nosesearch"
     return 0
  fi

  local LF="
"
  local result=0
  local RULE="$(echo "$1" | tr ',:&;' '    ' | tr -s ' ')"
  local expected_result="${2:-0}"
  local comment="$3"
  # TODO: takes ~1 second, abstract to a separate function that remembers
  #       the version in some __INTERNAL_rlSE_* variable
  if sesearch --version 2>&1 | grep -q '3.[0123]' ; then
    local SETOOLS_VER=3
    local SESEARCH_OPTS='-C'
  else # setools v.4
    local SETOOLS_VER=4
    local SESEARCH_OPTS=''
  fi
  rlIsRHEL '<6' && SESEARCH_OPTS="-i -n $SESEARCH_OPTS"

  rlLogInfo "$FUNCNAME: ${comment:-"checking rule '$1'"}"

  `rlSELogVar 'RULE'`
  # get policy type
  local POLICY="$__INTERNAL_POLICY_NAME"
  local POLICY_PATH=''
  [[ "$RULE" =~ $(echo '(.*)\s+(mls|targeted|minimum|strict)') ]] && {
    rlLogDebug "$FUNCNAME: POLICY PARSE"; `rlSELogVar 'BASH_REMATCH'`
    POLICY="${BASH_REMATCH[2]}"
    RULE="${BASH_REMATCH[1]}"
    `rlSELogVar 'RULE'`
    POLICY_PATH="$__INTERNAL_POLICY_ROOT/$POLICY/policy/policy.$(ls -1 -d $__INTERNAL_POLICY_ROOT/$POLICY/policy/policy.* | sed -r 's/[^.]*\.//' | sort -nr | head -n 1)"
  }
  `rlSELogVar 'POLICY' 'POLICY_PATH' RULE`

  # check typeattribute rule
                 #  -   typeattribute  TYPE      ATTR ...
  [[ "$RULE" =~ $(echo 'typeattribute\s+(\S+)\s+(\S+.*)') ]] && {
    rlLogDebug "$FUNCNAME(): typeattribute PARSE"; `rlSELogVar 'BASH_REMATCH'`
    local TYPE="${BASH_REMATCH[1]}"
    local ATTRIBUTE=( ${BASH_REMATCH[2]} )
    `rlSELogVar 'TYPE' 'ATTRIBUTE'`
    local seinfo_out
    while [[ -n "$ATTRIBUTE" ]]; do
      rlLogDebug "$FUNCNAME(): EXECUTING seinfo_out=\"\$(seinfo -xa$ATTRIBUTE $POLICY_PATH)\""
      seinfo_out="$(seinfo -xa$ATTRIBUTE $POLICY_PATH)"
      if [[ $? -ne 0 ]] ; then
        rlLogError "$FUNCNAME: seinfo failed"
        rlLogError "$FUNCNAME: $seinfo_out"
        let result++
      fi
      rlLogDebug "$FUNCNAME(): EXECUTING echo \"\$seinfo_out\" | grep -q \"\<${TYPE}\>\""
      echo "$seinfo_out" | grep -q "\<${TYPE}\>"
      rlAssertEquals "${comment:-"check if type '$TYPE' is present in attribute '$ATTRIBUTE' in policy '$POLICY'"}" $? $expected_result || let result++
      ATTRIBUTE=( "${ATTRIBUTE[@]:1}" )
    done
    return $result
  }

  # check other rules (allow, dontaudit, type_transition)

  # look for conditional boolean
  local BOOLEAN='.*'
  [[ "$RULE" =~ $(echo '(.*)(\s+\[(.*)\])(.*)') ]] && {
    rlLogDebug "$FUNCNAME(): BOOLEAN PARSE"; `rlSELogVar 'BASH_REMATCH'`
    BOOLEAN=( ${BASH_REMATCH[3]} )
    RULE="${BASH_REMATCH[1]}${BASH_REMATCH[4]}"
  }
  `rlSELogVar 'BOOLEAN' RULE`

  # actually check the rules
    # T/F  RULETYPE       SCONTEXT  TCONTEXT  CLASS    <PERM|{ PREMs }>
  [[ "$RULE" =~ $(echo '((T|F)\s+)?(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)') ]] && {
    rlLogDebug "$FUNCNAME(): RULE PARSE"; `rlSELogVar 'BASH_REMATCH'`
    local TF="${BASH_REMATCH[2]}"
    local RULETYPE="${BASH_REMATCH[3]}"
    local SCONTEXT="${BASH_REMATCH[4]}"
    local TCONTEXT="${BASH_REMATCH[5]}"
    local CLASS="${BASH_REMATCH[6]}"
    local PERM="${BASH_REMATCH[7]}"
    local TRANS_FILE=''
    if rlIsRHEL '<6'; then
    rlLogDebug "$FUNCNAME(): RULE PARSE"; `rlSELogVar 'BASH_REMATCH'`
      rlLogDebug "$FUNCNAME(): excluding permission 'open'"
      # for RHEL < 6 ignore open permission as it isnot defined there
      local PERM=( $(echo "${PERM}" | tr -d '{}' | sed -r 's/\<open\>//g') )
    else
      local PERM=( $(echo "${PERM}" | tr -d '{}') )
    fi

    local SEARCH_RULETYPE="$RULETYPE"
    [[ "$RULETYPE" == "dontaudit" ]] && rlIsRHEL '<6' && SEARCH_RULETYPE="audit" # dontaudit rules are in --audit rule type
    if [[ "$RULETYPE" == "type_transition" ]]; then
      if [[ ${SETOOLS_VER} == "3" ]]; then
        SEARCH_RULETYPE="type" # type_transition rules are in --type rule type
      else # setools v.4
        SEARCH_RULETYPE="type_trans" # type_transition rules are in --type_trans rule type
      fi
      if [[ -n "${PERM[1]}" ]] ; then
        `rlSELogVar 'PERM'`
        TRANS_FILE="${PERM[1]}"
        unset PERM[1]
      fi
    fi
    # sesearch v.3 --type covers type_trans, type_member, type_change
    # sesearch v.4 recognizes 3 different options for ^^^
    if [[ "$RULETYPE" == "type_change" ]]; then
      if [[ ${SETOOLS_VER} == "3" ]]; then
        SEARCH_RULETYPE="type"
      else # setools v.4
        SEARCH_RULETYPE="type_change"
      fi
      if [[ -n "${PERM[1]}" ]] ; then
        `rlSELogVar 'PERM'`
        TRANS_FILE="${PERM[1]}"
        unset PERM[1]
      fi
    fi

    # replace 'self' target context by source context
    [[ "$TCONTEXT" == "self" ]] && TCONTEXT="$SCONTEXT"
    `rlSELogVar 'TF' 'RULETYPE' 'SCONTEXT' 'TCONTEXT' 'CLASS' 'PERM' 'TRANS_FILE' 'SEARCH_RULETYPE'`

    # get rules from sesearch
    local ssearch="sesearch $SESEARCH_OPTS --$SEARCH_RULETYPE -s $SCONTEXT -t $TCONTEXT -c $CLASS $POLICY_PATH"
    `rlSELogVar ssearch`
    local RULES=$(eval $ssearch) || let result++
    [[ -n "$DEBUG" ]] && echo "ALL RULES${LF}$RULES"

    # filter rules specificly for type_transition
    if [[ -n "$TRANS_FILE" ]]; then
      # TODO: setools v4.1 quotes all filenames, v4.2 only those with spaces
      RULES=$(echo "$RULES" | grep -E "\<${TRANS_FILE}\>")
    fi

    # filter rules according to BOOLEAN
    if [[ "$BOOLEAN" == "" ]]; then
      # filter out all rules depending on booleans
      rlLogDebug "$FUNCNAME(): excluding conditional rules"
      rlLogDebug "$FUNCNAME(): EXECUTING echo \"\$RULES\" | grep -v '\['"
      RULES=$(echo "$RULES" | grep -v '\[')
      rlLogDebug "$FUNCNAME(): RULES${LF}$RULES"
    elif [[ "$BOOLEAN" != ".*" ]]; then
      # filter out rules without boolean $BOOLEAN
      rlLogDebug "$FUNCNAME(): pick only conditional rules using '$BOOLEAN'"
      while [[ -n "$BOOLEAN" ]]; do
        BOOLEAN="$(rlSETranslateBoolean "$BOOLEAN")"
        rlLogDebug "$FUNCNAME(): EXECUTING echo \"\$RULES\" | grep -E \"\[.*\<${BOOLEAN}\>.*\]\""
        RULES=$(echo "$RULES" | grep -E "\[.*\<${BOOLEAN}\>.*\]")
        BOOLEAN=( "${BOOLEAN[@]:1}" )
      done
      rlLogDebug "$FUNCNAME(): RULES${LF}$RULES"
      [[ -n "$TF" ]] && {
        rlLogDebug "$FUNCNAME(): pick only $TF rules"
        rlLogDebug "$FUNCNAME(): EXECUTING echo \"\$RULES\" | grep -P \"^[ED]$TF\""
        RULES=$(echo "$RULES" | grep -P "^[ED]$TF")
        rlLogDebug "$FUNCNAME(): RULES${LF}$RULES"
      }
    fi
    echo "FILTERED RULES${LF}$RULES"

    # loop over permissions
    while [[ -n "$PERM" ]]; do
      local SEARCHFOR="\<${RULETYPE}\>.+\<${CLASS}\>.+\<${PERM}\>"
      `rlSELogVar SEARCHFOR`
      echo "$RULES" | grep -Eq "$SEARCHFOR"
      rlAssertEquals "  check permission '$PERM' is present" $? $expected_result || let result++
      PERM=( "${PERM[@]:1}" )
    done
    return $result
  }

}

true <<'=cut'
=pod

=head2 rlSEMatchPathCon

Runs matchpathcon and checks if matchpathcon called on PATH returns context which
contains the STRING preceeded by colon. The function prints the result of matchpathcon
anyway.

If variable COLLECTIONS exists, the function will test all collection paths
containing requested path.

    rlSEMatchPathCon "/var/www/html" "http_sys_content_t"

=cut


function rlSEMatchPathCon() {

    if [ -e /var/run/nomatchpathcon ]; then
        echo "rlSEMatchPathCon disabled by /var/run/nomatchpathcon"
        return
    fi

    local FILE_PATH
    local LINK_PATH
    local REAL_TYPE=`rlSETranslateAlias $2`

    FILE_PATH=$1
    if ! rlIsRHEL '<6'; then
        local CL=( $COLLECTIONS )
        while [[ -n "$CL" ]]; do
           local p="/opt/rh/${CL}/root$1"
           [[ -e "$p" ]] && FILE_PATH=( "${FILE_PATH[@]}" "$p" )
           CL=( "${CL[@]:1}" )
        done
    fi

    local ec=0
    while [[ -n "$FILE_PATH" ]]; do
        if [ -L ${FILE_PATH} ] ; then
            LINK_PATH=`readlink -f ${FILE_PATH}`
            matchpathcon ${FILE_PATH} ${LINK_PATH}
            matchpathcon ${FILE_PATH} ${LINK_PATH} | grep :${REAL_TYPE} > /dev/null
            rlAssert0 "Results of matchpathcon ${FILE_PATH} ${LINK_PATH} should contain ${REAL_TYPE}" $? || ec=1
        else
            matchpathcon ${FILE_PATH}
            matchpathcon ${FILE_PATH} | grep :${REAL_TYPE} > /dev/null
            rlAssert0 "Result of matchpathcon ${FILE_PATH} should contain ${REAL_TYPE}" $? || ec=1
        fi
        FILE_PATH=( "${FILE_PATH[@]:1}" )
    done

    return $ec
}

__INTERNAL_rlSEgetsebool() {
  getsebool $(rlSETranslateBoolean ${1})
}


__INTERNAL_rlSEGetBooleanName() {
  __INTERNAL_rlSEgetsebool ${1} | cut -d ' ' -f 1
}


#      boolean name  current  persistent
# returns <BOOLEAN> <on|off> <on|off>
__INTERNAL_rlSEBooleanState() {
  local tmp=''
  local tmp2=''
  local boolean="$(rlSETranslateBoolean "$1")"
  tmp="$(paste <(getsebool ${boolean:--a} | sort) <(seinfo -b$boolean -x $__INTERNAL_POLICY_FILE 2>/dev/null | grep -iE 'true|false' | tr 'A-Z' 'a-z' | sed -r 's/\<false\>/off/g;s/\<true\>/on/g' | sort))"
  rlLogDebug "$FUNCNAME(): $tmp"
  tmp2="$(echo "$tmp" | sed -r 's/^(\S+).*\<(on|off)\>.*\<(on|off)\>.*/\1 \2 \3/')"
  rlLogDebug "$FUNCNAME(): $tmp2"
  while read -r line; do
    [[ "$line" =~ ^[a-zA-Z_0-9]+\ +(on|off)\ +(on|off)$ ]] || {
      rlLogError "error parsing boolean info '$line', expected format is BOOLEAN (on|off) (on|off)"
      rlLogError "  first state is a current state got from getsebool, second state is a persistent state got from seinfo"

    }
  done <<< "$tmp2"
  echo "$tmp2"
}


true <<'=cut'
=pod

=head2 rlSEBooleanBackup

The function to backup both current and default state of all or specified the
SELinux booleans, which is then restored by rlSEBooleanRestore function.

    rlSEBooleanBackup [--namespace NAMESPACE] [BOOLEAN ...]

=cut

# Usage: rlSEBooleanBackup
function rlSEBooleanBackup() {
    local NAMESPACE="$__INTERNAL_rlSE_NAMESPACE"

    while [[ "${1:0:1}" == "-" ]]; do
        case $1 in
          --namespace)
              shift
              NAMESPACE="$1"
            ;;
        esac
        shift
    done

    local STATUSFILE="$BEAKERLIB_DIR/sebooleans${NAMESPACE}"
    local res=0
    if [[ -z "$1" ]]; then
      if [ -f $STATUSFILE ]; then
        rlLogError "$FUNCNAME: Backup file already exists. Backing up all the booleans would erase the current backup."
        return 33
      fi
      touch $STATUSFILE
      rlLog "$FUNCNAME: Backing up the current state of all the SELinux booleans"
      __INTERNAL_rlSEBooleanState > $STATUSFILE
      res=$?
    else
      # if we didn't save the status yet, save it now
      local BOOLEAN
      while [[ -n "$1" ]]; do
        BOOLEAN="$1"
        touch "$STATUSFILE"
        if ! grep -q "^$BOOLEAN " "$STATUSFILE"; then
          local tmp="$(__INTERNAL_rlSEBooleanState $BOOLEAN)"
          [[ -n "$tmp" ]] && echo "$tmp" >> "$STATUSFILE" || let res++
        fi
        shift
      done
    fi
    return $res
}


true <<'=cut'
=pod

=head2 rlSEBooleanOn, rlSEBooleanOff

The functions to switch SELinux booleans (current or default value using -P) on/off. When executed for the first time, it remembers the initial status which is restored later on by rlSEBooleanRestore.

    rlSEBooleanOn [--namespace NAMESPACE] [-P] boolean1 [boolean2 ...]
    rlSEBooleanOff [--namespace NAMESPACE] [-P] boolean1 [boolean2 ...]

=cut

rlSEBooleanOn() {
	if [ -z "$1" ]; then
		rlLogError "$FUNCNAME: Missing arguments"
		return 1
	fi

    local PERMANENT=''
    local PERMANENT_MSG=''
    while [[ "${1:0:1}" == "-" ]]; do
        case $1 in
          --namespace)
              shift
              local __INTERNAL_rlSE_NAMESPACE="$1"
            ;;
          -P)
              PERMANENT=' -P '
              PERMANENT_MSG=" permanently"
            ;;
        esac
        shift
    done

	if [ -z "$1" ]; then
		rlLogError "$FUNCNAME: Missing arguments"
		return 1
	fi

	local new_states=''

	local FAILURES=0
	rlLog "$FUNCNAME: Setting SELinux booleans$PERMANENT_MSG on: $*"
	while [ -n "$1" ]; do
		local BOOLEAN=$(__INTERNAL_rlSEGetBooleanName "$1")
		[[ -z "$BOOLEAN" ]] && {
			rlLogError "$FUNCNAME: boolean name '$1' not found."
			FAILURES=$(( $FAILURES + 1 ))
			shift
			continue
		}
		[[ "$1" != "$BOOLEAN" ]] && {
			rlLogInfo "$FUNCNAME: using boolean name '$BOOLEAN' instead of '$1'"
		}
		# backup current state
		if ! rlSEBooleanBackup "$BOOLEAN"; then
			FAILURES=$(( $FAILURES + 1 ))
			rlLogError "$FUNCNAME: Backing up the $BOOLEAN boolean failed"
		fi

		new_states+="$BOOLEAN=on "
		shift
	done

	[[ -n "$new_states" ]] && {
	  setsebool $PERMANENT $new_states || {
		FAILURES=$(( $FAILURES + 1 ))
		rlLogError "$FUNCNAME: Setting boolean(s) to true failed"
	  }
	}
	return $FAILURES
}

rlSEBooleanOff() {
	if [ -z "$1" ]; then
		rlLogError "$FUNCNAME: Missing arguments"
		return 1
	fi

    local PERMANENT=''
    local PERMANENT_MSG=''
    while [[ "${1:0:1}" == "-" ]]; do
        case $1 in
          --namespace)
              shift
              local __INTERNAL_rlSE_NAMESPACE="$1"
            ;;
          -P)
              PERMANENT=' -P '
              PERMANENT_MSG=" permanently"
            ;;
        esac
        shift
    done


	if [ -z "$1" ]; then
		rlLogError "$FUNCNAME: Missing arguments"
		return 1
	fi

	local new_states=''

	local FAILURES=0
	rlLog "$FUNCNAME: Setting SELinux booleans$PERMANENT_MSG off: $*"

	while [ -n "$1" ]; do

		local BOOLEAN=$(__INTERNAL_rlSEGetBooleanName "$1")
		[[ -z "$BOOLEAN" ]] && {
			rlLogError "$FUNCNAME: boolean name '$1' not found."
			FAILURES=$(( $FAILURES + 1 ))
			shift
			continue
		}
		[[ "$1" != "$BOOLEAN" ]] && {
			rlLogInfo "$FUNCNAME: using boolean name '$BOOLEAN' instead of '$1'"
		}
		# backup current state
		if ! rlSEBooleanBackup "$BOOLEAN"; then
			FAILURES=$(( $FAILURES + 1 ))
			rlLogError "$FUNCNAME: Backing up the $BOOLEAN boolean failed"
		fi

		new_states+="$BOOLEAN=off "
		shift
	done

	[[ -n "$new_states" ]] && {
	  setsebool $PERMANENT $new_states || {
		FAILURES=$(( $FAILURES + 1 ))
		rlLogError "$FUNCNAME: Setting boolean(s) to false failed"
	  }
	}
	return $FAILURES
}


true <<'=cut'
=pod

=head2 rlSEBooleanRestore

Restores the original state of SELinux boolean(s) backed up by rlSEBooleanOn/Off
or rlSEBooleanBackup - all backed up booleans if none specified.
If there was no boolean backed up; either by rlSEBooleanOn/Off or
rlSEBooleanBackup the function logs an error and returns code 99.

    rlSEBooleanRestore [--namespace NAMESPACE] [boolean1 ...]

=cut

function rlSEBooleanRestore() {
    local NAMESPACE='' tmp
    while [[ "${1:0:1}" == "-" ]]; do
        case $1 in
          --namespace)
              shift
              NAMESPACE="$1"
            ;;
        esac
        shift
    done

	local FAILURES=0
    if [ ! -f $BEAKERLIB_DIR/sebooleans${NAMESPACE} ]; then
        rlLogError "$FUNCNAME: cannot restore SELinux booleans, saved states are not available"
        return 99
    fi

    local STATUSFILE="$(cat $BEAKERLIB_DIR/sebooleans${NAMESPACE})"

    local CHANGED_BOOLEANS=''
    local CURRENT_STATES=''
    local persistent_states=''
    local current_states=''
    local BOOLEAN

    # populate booleans list and current states
    if [ -z "$1" ]; then # no booleans specified, restoring all booleans
        rlLog "$FUNCNAME: restoring all backed up SELinux booleans"
        CURRENT_STATES="$(__INTERNAL_rlSEBooleanState)"
        CHANGED_BOOLEANS="$(diff <( echo "$STATUSFILE" ) <( echo "$CURRENT_STATES" ) | grep '<' | sed 's/< //' | awk '{ print $1 }')"
    else      # restoring only specified booleans
        rlLog "$FUNCNAME: restoring original status of SELinux booleans: $*"
        while [ -n "$1" ]; do # process all passed booleans
            BOOLEAN=$(__INTERNAL_rlSEGetBooleanName "$1")
            [[ -z "$BOOLEAN" ]] && {
              let FAILURES++
              rlLogError "$FUNCNAME: cannot restore SELinux boolean $1, which does not exist!"
              shift
              continue
            }
            rlLogDebug "$FUNCNAME(): using actual boolean name '$BOOLEAN'"
            CURRENT_STATES+="$(__INTERNAL_rlSEBooleanState $BOOLEAN)"$'\n'
            CHANGED_BOOLEANS+="$BOOLEAN"$'\n'
            shift
        done
    fi

    # create lists of pesistent and current states to restore
    while read BOOLEAN; do
        [[ -z "$BOOLEAN" ]] && continue
        `rlSELogVar BOOLEAN`
        tmp="\<${BOOLEAN} (\S+) (\S+)"
        if ! [[ "$STATUSFILE" =~ $tmp ]]; then
          let FAILURES++
          rlLogError "$FUNCNAME: cannot restore SELinux boolean $BOOLEAN, original state was not saved"
          shift
          continue
        fi
        BACKUP_STATE="${BASH_REMATCH[1]}"
        BACKUP_DEFAULT_STATE="${BASH_REMATCH[2]}"
        `rlSELogVar BASH_REMATCH BACKUP_STATE BACKUP_DEFAULT_STATE`
        if ! [[ "$CURRENT_STATES" =~ $tmp ]]; then
          let FAILURES++
          rlLogError "$FUNCNAME: cannot restore SELinux boolean $BOOLEAN, current state not available"
          shift
          continue
        fi
        CURRENT_STATE="${BASH_REMATCH[1]}"
        CURRENT_DEFAULT_STATE="${BASH_REMATCH[2]}"
        `rlSELogVar BASH_REMATCH CURRENT_STATE CURRENT_DEFAULT_STATE`

        if [[ "$CURRENT_DEFAULT_STATE" != "$BACKUP_DEFAULT_STATE" ]]; then
          persistent_states+="$BOOLEAN=$BACKUP_DEFAULT_STATE "
          current_states+="$BOOLEAN=$BACKUP_STATE "
          CURRENT_STATE=$BACKUP_DEFAULT_STATE
        fi
        if [[ "$CURRENT_STATE" != "$BACKUP_STATE" ]]; then
          current_states+="$BOOLEAN=$BACKUP_STATE "
        fi
    done <<< "$CHANGED_BOOLEANS"

    # do the actual restoration
    [[ -n "$persistent_states" ]] && {
      rlLogInfo "$FUNCNAME: restoring boolean persistent states"
      rlLogDebug "$FUNCNAME(): $persistent_states"
      setsebool -P $persistent_states || {
        let FAILURES++
        rlLogError "$FUNCNAME: setting boolean(s) failed"
      }
    }
    [[ -n "$current_states" ]] && {
      rlLogInfo "$FUNCNAME: restoring boolean current states"
      rlLogDebug "$FUNCNAME(): $current_states"
      setsebool $current_states || {
        let FAILURES++
        rlLogError "$FUNCNAME: setting boolean(s) failed"
      }
    }
    return $FAILURES
}

true <<'=cut'
=pod

=head2 rlSEMatchPortCon

Runs seinfo and checks if a SELinux port of type $1 (tcp/udp) and of number $2 is known under context type $3.  Required parameters and their order: port type, port number, SELinux context type.

    rlSEMatchPortCon PROTO NUMBER TYPE
    rlSEMatchPortCon tcp 80 "http_port_t"

=cut


function rlSEMatchPortCon() {

    if [ -e /var/run/nomatchportcon ]; then
        echo "rlSEMatchPortCon disabled by /var/run/nomatchportcon"
        return
    fi

    if ! seinfo --version | grep -q '3.[0123]' ; then
        # setools v.4
        rlRun "seinfo --portcon=$2 | grep \"portcon $1 .*:$3\""
    elif rlIsRHEL 5 ; then
        rlRun "seinfo -l$1 -p$2 | grep \"portcon.*:$3\""
    else
        rlRun "seinfo --protocol=$1 --portcon=$2 | grep \"portcon.*:$3\""
    fi
}

true <<'=cut'
=pod

=head2 rlSEPortAdd

# Add context type to given port if not in the current policy. The current state of the port contexts is backed up and can be restored by rlSEPortRestore.

    rlSEPortAdd PROTO NUMBER CONTEXT_TYPE

=cut

function rlSEPortAdd() {
    local RES
    local NAMESPACE=''
    while [[ "${1:0:1}" == "-" ]]; do
        case $1 in
          --namespace)
              shift
              NAMESPACE="_$1"
            ;;
        esac
        shift
    done

    if ! seinfo --version | grep -q '3.[0123]' ; then
        # setools v.4
        seinfo --portcon=$2 | grep "portcon $1 .*:$3"
        RES=$?
    elif rlIsRHEL 5 ; then
        seinfo -l$1 -p$2 | grep "portcon $1 $2 .*:$3"
        RES=$?
    else
        seinfo --protocol=$1 --portcon=$2 | grep "portcon $1 .*$2.*:$3"
        RES=$?
    fi

    if [ $RES -eq 0 ]; then
        rlLog "$FUNCNAME: The type $3 of $1 port $2 already in policy"
    else

        if ! seinfo --version | grep -q '3.[0123]' ; then
            # setools v.4
            seinfo --portcon=$2 | grep "portcon $1 \<$2\>"
            RES=$?
        elif rlIsRHEL 5 ; then
            seinfo -l$1 -p$2 | grep 'portcon $1 \<$2\>'
            RES=$?
        else
            seinfo --protocol=$1 --portcon=$2 | grep "portcon $1 \<$2\>"
            RES=$?
        fi

        local CHANGED_PORT_CONTEXTS="$(__INTERNAL_ST_GET ${NAMESPACE:+--namespace "$NAMESPACE"} rlSE_CHANGED_PORT_CONTEXTS)"

        if [ $RES -eq 0 ]; then
            rlLog "$FUNCNAME: Setting context type $3 to $1 port $2"
            rlRun "semanage port -m -t $3 -p $1 $2"
            if [ $? -eq 0 ]; then
                CHANGED_PORT_CONTEXTS="$CHANGED_PORT_CONTEXTS $1:$2:$3"
            fi
        else
            rlLog "$FUNCNAME: Setting context type $3 to $1 port $2"
            rlRun "semanage port -a -t $3 -p $1 $2"
            if [ $? -eq 0 ]; then
                CHANGED_PORT_CONTEXTS="$CHANGED_PORT_CONTEXTS $1:$2:$3"
            fi
        fi
        __INTERNAL_ST_PUT ${NAMESPACE:+--namespace "$NAMESPACE"} rlSE_CHANGED_PORT_CONTEXTS "$CHANGED_PORT_CONTEXTS"
    fi
}

true <<'=cut'
=pod

=head2 rlSEPortRestore

# Rollbacks port contexts set by rlSEPortAdd function. Restore all if not specified.

    rlSEPortRestore

=cut

function rlSEPortRestore() {
    local ITEM
    local TYPE
    local PROTO
    local PORT
    local NEWLIST
    local NAMESPACE=''
    while [[ "${1:0:1}" == "-" ]]; do
        case $1 in
          --namespace)
              shift
              NAMESPACE="_$1"
            ;;
        esac
        shift
    done
    local CHANGED_PORT_CONTEXTS=$(__INTERNAL_ST_GET ${NAMESPACE:+--namespace "$NAMESPACE"} rlSE_CHANGED_PORT_CONTEXTS)

    if [ ! $# -lt 1 ]; then
        NEWLIST=""
        for ITEM in $CHANGED_PORT_CONTEXTS; do
            if [ $ITEM == "$1:$2:$3" ]; then
                rlLog "$FUNCNAME: Removing context type $3 to $1 port $2"
                rlRun "semanage port -d -t $3 -p $1 $2"
            else
                NEWLIST="$NEWLIST $ITEM"
            fi
        done
        CHANGED_PORT_CONTEXTS=$NEWLIST

    else

        for ITEM in $CHANGED_PORT_CONTEXTS; do
            TYPE=`echo $ITEM | cut -f 3 -d ':'`
            PROTO=`echo $ITEM | cut -f 1 -d ':'`
            PORT=`echo $ITEM | cut -f 2 -d ':'`
            rlLog "$FUNCNAME: Removing context type $TYPE to $PROTO port $PORT"
            rlRun "semanage port -d -t $TYPE -p $PROTO $PORT"

        done
        CHANGED_PORT_CONTEXTS=""
    fi
    __INTERNAL_ST_PUT ${NAMESPACE:+--namespace "$NAMESPACE"} rlSE_CHANGED_PORT_CONTEXTS "$CHANGED_PORT_CONTEXTS"
}



true <<'=cut'
=pod

=head2 rlSESetTimestamp, rlSECheckAVC, rlSEAVCCheck

Pair functions to check AVC messages from the given moment. The starting timestamps can be named to be able to mark more than one moment.

    # Beginning of the phase/test:
    rlSESetTimestamp [timestamp_name]

    # End of the phase/test, count only unignored AVCs/ERRORs:
    rlSECheckAVC [--no-ignore] [--ignore REG_EXP [--ignore REG_EXP]] [timestamp_name]

    # or check without assert, prints number of unignored and unexpected AVCs/ERRORs, returns 0 if no unignored AVC/ERROR found:
    rlSEAVCCheck [--no-ignore] [--ignore REG_EXP [--ignore REG_EXP]] [--expect REG_EXP [--expect REG_EXP]] [timestamp_name]

=cut

function rlSESetTimestamp() {

    local STAMP=`date "+%m/%d/%Y %T"`
    local NAME="TIMESTAMP"

    [ -z "$1" ] || NAME="${NAME}_$1"
    eval "export __INTERNAL_rlSE_$NAME='$STAMP'"
    rlLog "$FUNCNAME: Setting timestamp '$NAME' [$STAMP]"

}

function rlSECheckAVC() {

    rlSEAVCCheck "$@" > /dev/null
    rlAssert0 'Check there are no unexpected AVCs/ERRORs' $?

}

function rlSEAVCCheck() {
    local NAME="TIMESTAMP"
    local ignore=('type=USER_AVC.*received (policyload|setenforce) notice')
    local ignore_internal='type=(SYSCALL|PATH|CWD|PROCTITLE|SOCKETCALL|OBJ_PID|SOCKADDR)'
    local expect
    rlLogDebug "$FUNCNAME(): process options"
    local GETOPT=$(getopt -q -o ni:e: -l no-ignore,ignore:,expect:,expected: -- "$@")
    eval set -- "$GETOPT"
    while [[ -n "$@" ]]; do
      case $1 in
      --)
        shift; break
        ;;
      -n|--no-ignore)
        ignore=()
        ;;
      -i|--ignore)
        shift
        ignore+=("$1")
        ;;
      -e|--expect|--expected)
        shift
        expect+=("$1")
        ;;
      *)
        echo "unknown option '$1'"
        return 1
        ;;
      esac
      shift;
    done

    [ -z "$1" ] || NAME="${NAME}_$1"

    local STAMP
    eval "STAMP=\"\$__INTERNAL_rlSE_$NAME\""
    `rlSELogVar expect ignore ignore_internal STAMP`
    if [ -z "$STAMP" ]; then
        rlLogError "$FUNCNAME: Timestamp $NAME is not defined"
        return 1
    else
        rlLog "$FUNCNAME: Search for AVCs, USER_AVCs, SELINUX_ERRs, and USER_SELINUX_ERRs since timestamp '$NAME' [$STAMP]"
        local ausearch_output=$(LC_TIME='en_US.UTF-8' ausearch -i -m AVC -m USER_AVC -m SELINUX_ERR -m USER_SELINUX_ERR -ts $STAMP 2>&1)
        echo "$ausearch_output" >&2
        local res=0
        # filter out ignored patterns
        [[ -n "${ignore[*]}" ]] && {
          rlLogInfo "$FUNCNAME: ignoring patterns:"
          local i
          for i in "${ignore[@]}"; do
            rlLogInfo "$FUNCNAME:     $i"
            ignore_internal="$ignore_internal|$i"
          done
        }
        rlLogDebug "$FUNCNAME(): filter out ignored patterns"
        ausearch_output="$(echo "$ausearch_output" | grep -Pi '^type=' | grep -vP "$ignore_internal")"
        `rlSELogVar ausearch_output`
        # find expected and filter then out; if not found, count them
        local exp
        [[ -n "${expect[*]}" ]] && rlLogInfo "$FUNCNAME: looking for expected patterns:"
        for exp in "${expect[@]}" ; do
          if echo "$ausearch_output" | grep -qP "$exp" ; then
            rlLogInfo    "$FUNCNAME:     ok   ... $exp"
            ausearch_output="$(echo "$ausearch_output" | grep -vP "$exp")"
          else
            rlLogWarning "$FUNCNAME:     fail ... $exp"
            let res++
          fi
        done
        `rlSELogVar res ausearch_output`
        # count the rest
        if [[ -n "$ausearch_output" ]] ; then
          let res+=$(echo "$ausearch_output" | wc -l)
          echo "---==============---" >&2
          echo "UNEXPECTED MESSAGES:" >&2
          echo "$ausearch_output" >&2
          echo "---==============---" >&2
        fi
        `rlSELogVar res`

        echo "$res"
        [[ "$res" -eq 0 ]]
        return $?
    fi

}




true <<'=cut'
=pod

=head2 rlSEIsMLS, rlSEIsTargeted, rlSEIsStrict, rlSEIsMinimum

The functions to check if desired policy is active at the moment. Returns 0 if true.

=cut


# tests whether MLS policy is used
function rlSEIsMLS() {
    sestatus | grep -qi mls$
}


# tests whether targeted policy is used
function rlSEIsTargeted() {
    sestatus | grep -qi targeted$
}


# tests whether strict policy is used
function rlSEIsStrict() {
    sestatus | grep -qi strict$
}


# tests whether minimum policy is used
function rlSEIsMinimum() {
    sestatus | grep -qi minimum$
}

true <<'=cut'
=pod

=head2 rlSEDefined

The functions to check if given types exist in the current policy and returns 0 if true.

    rlSEDefined httpd_t snmpd_t
=cut


# Searches for all the types given in the argument and returns 0 if all
# of them exist. Returns 1 otherwise.
function rlSEDefined() {
    local RET_VAL=0
    local TYPE

    for TYPE in $1 ; do
        # there are also type aliases in RHEL-7
        if seinfo -t$TYPE 2>&1 | grep -qi -e error -e 'types: 0' ; then
            echo "$TYPE is NOT defined"
            RET_VAL=1
        else
            echo "$TYPE is defined"
        fi
    done

    return $RET_VAL;
}



true <<'=cut'
=pod

=head2 rlSEStatus

Prints various SELinux information

   rlSEStatus                 # prints sestatus results
   rlSEStatus -b [regexp]     # prints all/selected booleans (from getsebool)
   rlSEStatus -p [regexp]     # prints all/selected ports (from semanage port -l)
   rlSEStatus -m [regexp]     # prints all/selected selinux modules (from semodule -l)
   rlSEStatus -em [regexp]    # prints all/selected enabled selinux modules
   rlSEStatus -dm [regexp]    # prints all/selected disabled selinux modules
   rlSEStatus -t [regexp]     # prints all/selected context types (from seinfo -t)

=cut

function rlSEStatus() {

    # -b parameter - print booleans
    if [ "$1" = "-b" ]; then
        rlRun "getsebool -a | grep \"$2\""
        return;
    fi

    # -p parameter - print ports
    if [ "$1" = "-p" ]; then
        rlRun "semanage port -l | grep \"$2\""
        return;
    fi

    # -m parameter - print selinux modules
    if [ "$1" = "-m" ]; then
        rlRun "semodule -l | grep \"$2\""
        return;
    fi

    # -em parameter - print enabled selinux modules
    if [ "$1" = "-em" ]; then
        rlRun "semodule -l | grep -v -i disabled | grep \"$2\""
        return;
    fi

    # -dm parameter - print disabled selinux modules
    if [ "$1" = "-dm" ]; then
        rlRun "semodule -l | grep -i disabled | grep \"$2\""
        return;
    fi

    # -t parameter - print types
    if [ "$1" = "-t" ]; then
        rlRun "seinfo -t | grep \"$2\""
        return;
    fi

    # Without any params - run sestatus
    rlRun "id -Z"
    rlRun "sestatus"
    if semodule --help | grep -qi "list-modules.*kind" ; then
        rlRun "semodule --list-modules=full | grep -i disabled" 0,1
    else
        rlRun "semodule -l | grep -i disabled" 0,1
    fi
}



true <<'=cut'
=pod

=head2 rlSERunWithPassword

The function executes given command and provides the password whenever prompted for password.
The password can be either stored in PASSWORD global variable or specified using -p parameter.

    rlSERunWithPassword [ -p PASSWORD ] COMMAND

=cut

function rlSERunWithPassword() {

  local PASS="$PASSWORD"
  # read password parameter
  if [ "$1" = "-p" ]; then
      PASS="$2"
      shift 2
  fi

  cat <<EOF | expect -
set timeout 5
spawn $*
expect {
  -re "assword:" { send "$PASS\r"; exp_continue }
}
EOF

}

true <<'=cut'
=pod

=head2 rlSEService

Runs given service using run_init tool and checks the context of the running process.

Usage:
    rlSEService ${ROOT_PASSWORD} ${SERVICE_NAME} ${PROCESS_NAME} ${PROCESS_CONTEXT} ${OPERATIONS}

Example:
    rlSEService "root_passwd" "httpd" "httpd" "httpd_t" "start status stop status"

=cut


function rlSEService() {
    local OPERATION
    local RET_VAL
    local REAL_TYPE

    for OPERATION in $5; do

        # Set the return value
        # Service status can return both 0 and 3
        if echo $OPERATION | grep -q status; then
            RET_VAL=0,1,3
        else
            RET_VAL=0
        fi

        # Run the service using run_init tool
        #rlRun "echo $1 | run_init service $2 $OPERATION" $RET_VAL
        if rlIsRHEL 5 6 ; then
            if rlSEIsMLS ; then
                rlRun "rlSERunWithPassword -p $1 run_init service $2 $OPERATION" $RET_VAL
            elif rlSEIsStrict ; then
                rlRun "rlSERunWithPassword -p $1 run_init service $2 $OPERATION" $RET_VAL
            else
                rlRun "service $2 $OPERATION" $RET_VAL
            fi
        else
            rlRun "service $2 $OPERATION" $RET_VAL
        fi

        REAL_TYPE=`rlSETranslateAlias $4`
        # Check context of the service process
        if echo $OPERATION | grep -q -e start -e reload ; then
            sleep $6
            if [ "$3" != "-" ] ; then
                rlRun "ps -efZ | grep -v \" grep \" | grep -E \"$3\""
                rlRun "ps -efZ | grep -v \" grep \" | grep -E \"${REAL_TYPE}.*$3\""
            fi
        fi

        # Wait given number of seconds
        if [ ! -z $6 ]; then
            sleep $6
        fi

    done
}


function rlSETransAndRun() {
  local TMPDIR
  local SELINUX_TYPE
  local CURRENT_CONTEXT

  if [ -f testpolicy.te ] ; then
    rlLog "$FUNCNAME: using a predefined local policy for the test"
    rlRun "ls -l testpolicy.*"
    rlRun "make -f /usr/share/selinux/devel/Makefile testpolicy.pp"
    rlRun "semodule -i testpolicy.pp"
    rm -rf tmp # by-product of the local policy module compilation
  else
    TMPDIR=`mktemp -d`
    SELINUX_TYPE=`echo $1 | cut -d : -f 3`
    CURRENT_CONTEXT=`id -Z`
    rlLog "$FUNCNAME: preparing a local policy which allows transition from $CURRENT_CONTEXT to $1"
    pushd ${TMPDIR}
    echo -e "policy_module(testpolicy,1.0)\n\nrequire {\n  type unconfined_t;  type $SELINUX_TYPE;\n  class process { transition };\n}\n\nallow unconfined_t $SELINUX_TYPE : process { transition };\n" > testpolicy.te
    rlRun "make -f /usr/share/selinux/devel/Makefile"
    rlRun "semodule -i testpolicy.pp"
    popd
    rm -rf ${TMPDIR}
  fi
  rlRun "runcon $1 bash -c \"$2\""
  rlRun "semodule -r testpolicy"
}


true <<'=cut'
=pod

=head2 rlSERunWithContext

Executes command with a given context. There has to be transition allowed from initrc_exec_t to a desired context available.

    rlSERunWithContext [-u USER] [-r ROLE] [-t TYPE] cmd
    e.g. rlRun "rlSERunWithContext -t smbd_exec_t stat $TmpDir/testmount"

=cut


# OPTIONS are supposed to be passed to chcon command
function rlSERunWithContext() {
    local TMPDIR
    local OPTIONS
    local COMMAND
    local RETCODE

    #read and store options
    while [ "${1:0:1}" = "-" ]; do
        OPTIONS+=" $1 $2"
        shift 2
    done
    if [ -z "$1" ]; then
        rlLogError "$FUNCNAME: No command passed to rlRunWithSELinuxContext"
        return 99
    else
        COMMAND=$@ # store command with arguments
    fi

    TMPDIR=`mktemp -d`
    chcon -t smbd_tmp_t $TMPDIR

    #prepare launcher scripts - one with initrc_exec_t and other with desired context
    echo -e "#!/bin/bash\n$TMPDIR/launcher2.sh\n" > $TMPDIR/launcher1.sh
    echo -e "#!/bin/bash\n$COMMAND" > $TMPDIR/launcher2.sh
    chcon -t initrc_exec_t $TMPDIR/launcher1.sh
    chcon $OPTIONS $TMPDIR/launcher2.sh
    chmod a+x $TMPDIR/*.sh
    #cat $TMPDIR/launcher1.sh
    #cat $TMPDIR/launcher2.sh

    $TMPDIR/launcher1.sh # execute the first launcher script
    RETCODE=$?

    rm -rf $TMPDIR
    return $RETCODE

}

true <<'=cut'
=pod

=head2 rlSETranslateBoolean

Some booleans were renamed during the time, but already written tests contain
boolean names which may not be current. The function takes a boolean name as an argument.
When executed on RHEL-5 or RHEL-6 the function returns old boolean name.
When executed on RHEL >= 7 the function returns new boolean name.
If the boolean was not renamed then the same boolean is returned.

    rlSETranslateBoolean BOOL_NAME

=cut

function rlSETranslateBoolean() {
    local FIELD LINE RENAMED_BOOLEANS

    if rlIsRHEL 5 > /dev/null 2>&1; then
        FIELD=2
    elif rlIsRHEL 6  > /dev/null 2>&1; then
        if [[ $1 == "clamscan_can_scan_system" ]] ||
           [[ $1 == "antivirus_can_scan_system" ]] ||
           [[ $1 == "amavis_use_jit" ]] ||
           [[ $1 == "clamd_use_jit" ]] ||
           [[ $1 == "antivirus_use_jit" ]] ; then
            FIELD=1
        else
            FIELD=2
        fi
    else
        FIELD=1
    fi

    RENAMED_BOOLEANS="
    antivirus_can_scan_system clamscan_can_scan_system
    antivirus_use_jit amavis_use_jit
    antivirus_use_jit clamd_use_jit
    auditadm_exec_content allow_auditadm_exec_content
    condor_tcp_network_connect condor_domain_can_network_connect
    cvs_read_shadow allow_cvs_read_shadow
    daemons_dump_core allow_daemons_dump_core
    daemons_use_tcp_wrapper allow_daemons_use_tcp_wrapper
    daemons_use_tty allow_daemons_use_tty
    domain_fd_use allow_domain_fd_use
    ftpd_anon_write allow_ftpd_anon_write
    ftpd_full_access allow_ftpd_full_access
    ftpd_use_cifs allow_ftpd_use_cifs
    ftpd_use_nfs allow_ftpd_use_nfs
    gssd_read_tmp allow_gssd_read_tmp
    guest_exec_content allow_guest_exec_content
    httpd_anon_write allow_httpd_anon_write
    httpd_mod_auth_ntlm_winbind allow_httpd_mod_auth_ntlm_winbind
    httpd_mod_auth_pam allow_httpd_mod_auth_pam
    httpd_sys_script_anon_write allow_httpd_sys_script_anon_write
    icecast_use_any_tcp_ports icecast_connect_any
    kerberos_enabled allow_kerberos
    login_console_enabled allow_console_login
    logwatch_can_network_connect_mail logwatch_can_sendmail
    mount_anyfile allow_mount_anyfile
    mplayer_execstack allow_mplayer_execstack
    named_tcp_bind_http_port named_bind_http_port
    nfsd_anon_write allow_nfsd_anon_write
    nis_enabled allow_ypbind
    polyinstantiation_enabled allow_polyinstantiation
    postfix_local_write_mail_spool allow_postfix_local_write_mail_spool
    postgresql_can_rsync sepgsql_enable_pitr_implementation
    postgresql_selinux_transmit_client_label sepgsql_transmit_client_label
    postgresql_selinux_unconfined_dbadm sepgsql_unconfined_dbadm
    postgresql_selinux_users_ddl sepgsql_enable_users_ddl
    puppetagent_manage_all_files puppet_manage_all_files
    rsync_anon_write allow_rsync_anon_write
    saslauthd_read_shadow allow_saslauthd_read_shadow
    secadm_exec_content allow_secadm_exec_content
    selinuxuser_direct_dri_enabled user_direct_dri
    selinuxuser_execheap allow_execheap
    selinuxuser_execmod allow_execmod
    selinuxuser_execstack allow_execstack
    selinuxuser_mysql_connect_enabled allow_user_mysql_connect
    selinuxuser_ping user_ping
    selinuxuser_postgresql_connect_enabled allow_user_postgresql_connect
    selinuxuser_rw_noexattrfile user_rw_noexattrfile
    selinuxuser_share_music user_share_music
    selinuxuser_tcp_server user_tcp_server
    smbd_anon_write allow_smbd_anon_write
    ssh_keysign allow_ssh_keysign
    staff_exec_content allow_staff_exec_content
    sysadm_exec_content allow_sysadm_exec_content
    user_exec_content allow_user_exec_content
    xguest_exec_content allow_xguest_exec_content
    xserver_clients_write_xshm allow_write_xshm
    xserver_execmem allow_xserver_execmem
    zebra_write_config allow_zebra_write_config
    "

    LINE="$(echo "${RENAMED_BOOLEANS}" | grep -E -- "\<${1}\>")"
    if [ $? -eq 0 ] ; then
        echo $LINE | cut -d ' ' -f ${FIELD}
    else
        echo $1
    fi

    return 0
}


true <<'=cut'
=pod

=head2 rlSETranslateAlias

If first parameter is an alias then the function returns the real type.
If first parameter is a real type then the function returns the real type.
Limitation: seinfo does not report aliases on RHEL-5 and RHEL-6 now.

    rlSETranslateAlias ALIAS

=cut

function rlSETranslateAlias {
    if rlIsRHEL 5 ; then
        echo $1
        return 0
    elif rlIsRHEL 6 ; then
        if seinfo -t$1 2>&1 | grep -q "ERROR:" ; then
            echo $1
            return 1
        elif seinfo -t$1 2>&1 | grep -q " $1" ; then
            echo $1
            return 0
        else # the type should be used either as a source or as a target in an allow rule
            ( sesearch -s $1 -A | tr -s ' ' | cut -d ' ' -f 3 ; sesearch -t $1 -A | tr -s ' ' | cut -d ' ' -f 4 ) | sort | uniq | grep "^.*_t$"
            return 0
        fi
    else
        local seinfo_out
        seinfo_out="$(seinfo -t$1 2>&1 )"
        if echo "$seinfo_out" | grep -q "ERROR:" ; then
            # the type was not recognized
            echo $1
            return 1
        elif echo "$seinfo_out" | grep -q "TypeName " ; then
            seinfo -t$1 2>/dev/null | grep TypeName | tr -s ' ' | cut -d ' ' -f 3
            return 0
        elif echo "$seinfo_out" | grep -q "Types: 0" ; then
            # cannot translate alias, if setools v.4 are used then BZ#1581761
            echo $1
            return 1
        elif seinfo --version | grep -q ^4 ; then
            # setools v.4
            seinfo -t$1 2>/dev/null | tail -n 1 | tr -s ' ' | cut -d ' ' -f 2
            return 0
        else
            # setools v.3
            seinfo -t$1 2>/dev/null | head -n 1 | tr -s ' ' | cut -d ' ' -f 2
            return 0
        fi
    fi
}

true <<'=cut'
=pod

=head2 rlSEListServices

There are many services which by default run on the same port.
The function returns a list of such services which run on given port.
Otherwise the function returns an empty list.

=cut

function rlSEListServices() {
    local SERVICES_ARRAY

    if [ $1 -lt 1 -o $1 -gt 65535 ] ; then
        rlLogError "$FUNCNAME: invalid port number"
        return 1
    fi

    SERVICES_ARRAY[21]='vsftpd proftpd pure-ftpd lighttpd' # FTP servers
    SERVICES_ARRAY[25]='exim postfix sendmail' # SMTP servers
    SERVICES_ARRAY[53]='named named-sdb unbound yadifad nsd pdns' # DNS servers
    SERVICES_ARRAY[80]='httpd cherokee lighttpd nginx thttpd' # HTTP servers
    SERVICES_ARRAY[123]='ntpd chronyd' # NTP servers

    echo -n ${SERVICES_ARRAY[$1]}
    return 0
}



true <<'=cut'
=pod

=head2 rlSESetEnforce

The functions sets selinux mode to Enforcing unless env. variable ENFORCING is set to 0. Then,
the permissive mode is set. Moreover, when the test is running in permissive mode, the function
thrown a WARN.

=cut

function rlSESetEnforce() {

    if [ "x$ENFORCING" != "x0" ]; then
        ENFORCING=1
    fi

    rlRun "setenforce $ENFORCING"

    getenforce | grep Permissive && rlLogWarning "$FUNCNAME: The test is running in SELinux permissive mode."

}



__INTERNAL_rlSEModuleList() {
  local semodule_list
  eval semodule_list="\$($__INTERNAL_SEMODULE_LISTING)";
  local res=$?
  echo "$semodule_list" | sed -r 's/^[0-9]+\s//'
  return $res
}


: <<'=cut'
=pod

=head2 rlSEModuleEnable

The function attempts to enable policy module(s).

    rlSEModuleEnable [--namespace NAMESPACE] MODULE ...

Return number of failures

See also rlSEModuleRestore

=cut

rlSEModuleEnable() {
  local NAMESPACE='' res=0
  while [[ "${1:0:1}" == "-" ]]; do
      case $1 in
        --namespace)
            shift
            NAMESPACE="_$1"
          ;;
      esac
      shift
  done
  local module semodule_list to_enable
  if semodule_list="$(__INTERNAL_rlSEModuleList)"; then
    for module in "$@" ; do
      local semodule="$(echo "$semodule_list" | grep -E "^${module}\s")"
      if [[ -z "$semodule" ]] ; then
        rlLogError "$FUNCNAME: module '$module' does not exist, skipping"
        let res++
      else
        local state="$(echo "$semodule" | grep -iqE '\sdisabled$' && echo disabled || echo enabled)"
        [[ -z "$(__INTERNAL_ST_GET ${NAMESPACE:+--namespace "$NAMESPACE"} --section=semodule $module)" ]] && \
          __INTERNAL_ST_PUT ${NAMESPACE:+--namespace "$NAMESPACE"} --section=semodule $module $state
          __INTERNAL_ST_PUT ${NAMESPACE:+--namespace "$NAMESPACE"} --section=semodule changed_modules "$(__INTERNAL_ST_GET ${NAMESPACE:+--namespace "$NAMESPACE"} --section=semodule changed_modules) $module"
        if [[ "$state" == "enabled" ]]; then
          rlLogInfo "$FUNCNAME: module '$module' is already enabled"
        else
          to_enable="$to_enable $module"
        fi
      fi
    done
    to_enable="${to_enable:1}"
    if [[ -n "$to_enable" ]]; then
      rlLog "$FUNCNAME: enabling '$to_enable' module(s), running 'semodule -e $to_enable'"
      semodule -e $to_enable
      local semodule_res=$?
      if [[ $semodule_res -eq 0 ]] ; then
        rlLog "$FUNCNAME: semodule enable passed"
      else
        rlLog "$FUNCNAME: semodule enable failed with exit code '$semodule_res'"
        let res++
      fi
    fi
  else
    rlLogError "$FUNCNAME: could not get modules list"
    let res++
  fi
  return $res
}


: <<'=cut'
=pod

=head2 rlSEModuleDisable

The function attempts to disable policy module(s).

    rlSEModuleDisable [--namespace NAMESPACE] MODULE ...

Return number of failures

See also rlSEModuleRestore

=cut

rlSEModuleDisable() {
  local NAMESPACE='' res=0
  while [[ "${1:0:1}" == "-" ]]; do
      case $1 in
        --namespace)
            shift
            NAMESPACE="_$1"
          ;;
      esac
      shift
  done
  local module semodule_list to_disable
  if semodule_list="$(__INTERNAL_rlSEModuleList)"; then
    for module in "$@" ; do
      local semodule="$(echo "$semodule_list" | grep -E "^${module}\s")"
      if [[ -z "$semodule" ]] ; then
        rlLogError "$FUNCNAME: module '$module' does not exist, skipping"
        let res++
      else
        local state="$(echo "$semodule" | grep -iqE '\sdisabled$' && echo disabled || echo enabled)"
        [[ -z "$(__INTERNAL_ST_GET ${NAMESPACE:+--namespace "$NAMESPACE"} --section=semodule $module)" ]] && \
          __INTERNAL_ST_PUT ${NAMESPACE:+--namespace "$NAMESPACE"} --section=semodule $module $state
          __INTERNAL_ST_PUT ${NAMESPACE:+--namespace "$NAMESPACE"} --section=semodule changed_modules "$(__INTERNAL_ST_GET ${NAMESPACE:+--namespace "$NAMESPACE"} --section=semodule changed_modules) $module"
        if [[ "$state" == "disabled" ]]; then
          rlLogInfo "$FUNCNAME: module '$module' is already disabled"
        else
          to_disable="$to_disable $module"
        fi
      fi
    done
    to_disable="${to_disable:1}"
    if [[ -n "$to_disable" ]]; then
      rlLog "$FUNCNAME: disabling '$to_disable' module(s), running 'semodule -d $to_disable'"
      semodule -d $to_disable
      local semodule_res=$?
      if [[ $semodule_res -eq 0 ]] ; then
        rlLog "$FUNCNAME: semodule disable passed"
      else
        rlLog "$FUNCNAME: semodule disable failed with exit code '$semodule_res'"
        let res++
      fi
    fi
  else
    rlLogError "$FUNCNAME: could not get modules list"
    let res++
  fi
  return $res
}


: <<'=cut'
=pod

=head2 rlSEModuleRestore

The function attempts to restore policy module(s) state present before
rlSEModuleEnable/rlSEModuleDisable was firstly called.

If no module is specified, all modules will be restored.

    rlSEModuleRestore [--namespace NAMESPACE] [MODULE ...]

Return number of failures

=cut

rlSEModuleRestore() {
  local NAMESPACE='' res=0
  while [[ "${1:0:1}" == "-" ]]; do
      case $1 in
        --namespace)
            shift
            NAMESPACE="_$1"
          ;;
      esac
      shift
  done
  local module semodule_list to_enable to_disable
  if semodule_list="$(__INTERNAL_rlSEModuleList)"; then
    local modules="$@"
    local changed_modules="$(__INTERNAL_ST_GET ${NAMESPACE:+--namespace "$NAMESPACE"} --section=semodule changed_modules)"
    [[ -z "$modules" ]] && modules="$changed_modules"
    for module in $modules ; do
      if [[ "$changed_modules" =~ $(echo "\<$module\>") ]] ; then
        changed_modules="$(echo "$changed_modules" | sed -r "s/\<${module}\>//")"
        __INTERNAL_ST_PUT ${NAMESPACE:+--namespace "$NAMESPACE"} --section=semodule changed_modules "$changed_modules"
        local semodule="$(echo "$semodule_list" | grep -E "^${module}\s")"
        if [[ -z "$semodule" ]] ; then
          rlLogError "$FUNCNAME: module '$module' does not exist, skipping"
          let res++
        else
          local state="$(echo "$semodule" | grep -iqE '\sdisabled$' && echo disabled || echo enabled)"
          local saved_state="$(__INTERNAL_ST_GET ${NAMESPACE:+--namespace "$NAMESPACE"} --section=semodule $module)"
          __INTERNAL_ST_PRUNE ${NAMESPACE:+--namespace "$NAMESPACE"} --section=semodule $module
          if [[ "$saved_state" == "enabled" ]] ; then
            if [[ "$state" == "enabled" ]]; then
              rlLogInfo "$FUNCNAME: module '$module' is already enabled"
            else
              to_enable="$to_enable $module"
            fi
          elif [[ "$saved_state" == "disabled" ]] ; then
            if [[ "$state" == "disabled" ]]; then
              rlLogInfo "$FUNCNAME: module '$module' is already disabled"
            else
              to_disable="$to_disable $module"
            fi
          else
            rlLogError "$FUNCNAME: unexpected saved state '$saved_state'"
            let res++
          fi
        fi
      else
        rlLogError "$FUNCNAME: there is no state of module '$module' saved, skipping"
        let res++
      fi
    done
    to_enable="${to_enable:1}"
    to_disable="${to_disable:1}"
    if [[ -n "$to_enable" ]]; then
      rlLog "$FUNCNAME: enabling '$to_enable' module(s), running 'semodule -e $to_enable'"
      semodule -e $to_enable
      local semodule_res=$?
      if [[ $semodule_res -eq 0 ]] ; then
        rlLog "$FUNCNAME: semodule enable passed"
      else
        rlLog "$FUNCNAME: semodule enable failed with exit code '$semodule_res'"
        let res++
      fi
    fi
    if [[ -n "$to_disable" ]]; then
      rlLog "$FUNCNAME: disabling '$to_disable' module(s), running 'semodule -d $to_disable'"
      semodule -d $to_disable
      local semodule_res=$?
      if [[ $semodule_res -eq 0 ]] ; then
        rlLog "$FUNCNAME: semodule disable passed"
      else
        rlLog "$FUNCNAME: semodule disable failed with exit code '$semodule_res'"
        let res++
      fi
    fi
  else
    rlLogError "$FUNCNAME: could not get modules list"
    let res++
  fi
  return $res
}


__INTERNAL_rlSEenable_full_auditing() {
  local rules_file=/etc/audit/rules.d/audit.rules
  if rlIsRHEL '<7'; then
    rules_file="/etc/audit/audit.rules"
  fi
  local final_rules=/etc/audit/audit.rules
  local config_file=/etc/audit/auditd.conf
  local auditd_need_restart=0
  local rules="-D"$'\n'"-w /etc/shadow -p w"
  local res=0
  if ! diff -u <(grep -v -e '^$' -e '^#' $final_rules) <(echo "$rules") > /dev/null; then
    echo "$rules" > ${rules_file} && {
      auditd_need_restart=1
    } || {
      rlLogError "could not enable full path resolving"
      let res++
    }
  fi
  rlIsRHEL '<7' || {
    if grep -q "log_format = ENRICHED" $config_file; then
      rlLog "enriched audit log format already enabled"
    else
      rlLog "enabling enriched audit log format"
      sed -r -i 's/log_format =.*/log_format = ENRICHED/' $config_file && {
        auditd_need_restart=1
      } || {
        rlLogError "could not enable ENRICHED logging"
        let res++
      }
    fi
  }
  [[ $auditd_need_restart -eq 1 ]] && {
    rlLog "stop the audit daemon first"
    rlRun "service auditd stop"
    sleep 5
    rlLog "audit daemon configuration file is updated, starting the audit service"
    rlServiceStart auditd || {
      rlLogError "audit daemon was not restarted correctly"
      let res++
    }
  }
  if ! diff -u <(grep -v -e '^$' -e '^#' $final_rules) <(echo "$rules") > /dev/null; then
    rlLogError "$final_rules is not updated"
    let res++
  fi
  return $res
}


__INTERNAL_rlSEcache_checksum() {
    local cachefile="$__INTERNAL_rlSE_CACHEFILE"
    local sumfile="$__INTERNAL_rlSE_SUMFILE"

    mkdir -p "$rlSE_CACHE_DIR" || {
        rlLogError "cannot create rule cache dir"
        return 1
    }
    local currentsum=$(sha1sum /sys/fs/selinux/policy) || {
        rlLogError "cannot sha1sum selinux policy in /sys"
        return 1
    }
    if [ -s "$cachefile" -a -s "$sumfile" ]; then
        oldsum=$(<"$sumfile")
        if [ "$currentsum" = "$oldsum" ]; then
            # checksums identical, cache still valid
            return 0
        fi
    fi
    # checksum nonexisten / different, overwrite old by current
    # and trigger cache rebuild
    echo "$currentsum" > "$sumfile"
    return 2
}

#
# COMPATIBILITY NOTES:
# - since rlSESearchRule doesn't use -p / --perms, we don't support it here,
#   but it should be easy to add if needed
# - multiple permissions of one original rule are split into multiple rows,
#   each with 1 permission
# - if searching by attribute in -s / -t, only rules specifying the attribute
#   are returned, not rules for all types they encompass
#   - searching by type works as with setools/sesearch
# - filename in type_transition rules is always returned in double quotes,
#   like setools v4.1, unlike setools v4.2+
#
__INTERNAL_rlSEcache_sesearch() {
    local opts=$(getopt -o "s:t:c:" -l "allow,dontaudit,type_trans" -- "$@" \
            2> >(while read -r line; do rlLogError "$FUNCNAME: $line"; done))
    [ $? -ne 0 ] && return 1

    eval set -- "$opts"
    local in_source= in_target= in_class= ruletype=
    while true; do
        case "$1" in
            '-s') shift; in_source="$1"; shift ;;
            '-t') shift; in_target="$1"; shift ;;
            '-c') shift; in_class="$1"; shift ;;
            '--allow') ruletype="allow"; shift ;;
            '--dontaudit') ruletype="dontaudit"; shift ;;
            '--type_trans') ruletype="type_trans"; shift ;;
            --) shift; break ;;
        esac
    done;

    local cachefile="$__INTERNAL_rlSE_CACHEFILE"
    if ! __INTERNAL_rlSEcache_checksum; then
        rlLogInfo "(re)creating selinux-policy rule cache"
        rm -f "$cachefile"
        "$rlSELibraryDir/mkcache.py" "$cachefile" || {
            rlLogError "cannot successfully create rule cache"
            rm -f "$cachefile"  # in case it is incomplete
            return 1
        }
    else
        rlLogInfo "using existing selinux-policy rule cache"
    fi

    case "$ruletype" in
        allow|dontaudit)
            local q="SELECT \"source\", \"target\", \"class\",
                            \"perm\", \"bool\", \"boolstate\"
                     FROM \"${ruletype}_lookup\"
                     WHERE
                         \"source\"='$in_source' AND \"target\"='$in_target'
                         AND \"class\"='$in_class' "
            #[ "$in_perm" ] && q+="AND \"perm\" IN ($in_perm) "
            local ret= row= source= target= class= perm= bool= bstate=
            while IFS= read -r row; do
                IFS='|' read -r source target class perm bool bstate <<<"$row"
                case "$perm" in *\ *) perm="{ $perm }" ;; esac  # more than one
                ret="$ruletype $source $target:$class $perm;"
                if [ "$bool" ]; then
                    ret+=" [ $bool ]:"
                    [ "$bstate" = "1" ] && ret+="True" || ret+="False"
                fi
                echo "$ret"
            done < <(echo "$q" | sqlite3 "$cachefile")
            ;;
        type_trans)
            local q="SELECT \"source\", \"target\", \"class\", \"default\",
                            \"filename\", \"bool\", \"boolstate\"
                     FROM \"${ruletype}_lookup\"
                     WHERE
                         \"source\"='$in_source' AND \"target\"='$in_target'
                         AND \"class\"='$in_class' "
            local ret= row= source= target= class= default= filename= bool= bstate=
            while IFS= read -r row; do
                IFS='|' read -r source target class default filename bool bstate <<<"$row"
                ret="type_transition $source $target:$class $default"
                [ "$filename" ] && ret+=" \"$filename\""
                ret+=';'
                if [ "$bool" ]; then
                    ret+=" [ $bool ]:"
                    [ "$bstate" = "1" ] && ret+="True" || ret+="False"
                fi
                echo "$ret"
            done < <(echo "$q" | sqlite3 "$cachefile")
            ;;
        *)
            rlLogError "unsupported cache rule type: $ruletype"
            return 1
            ;;
    esac
}

rlSELibraryLoaded() {
    return 0
}


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Authors
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

: <<'=cut'
=pod

=head1 AUTHORS

=over

=item *

Milos Malik <mmalik@redhat.com>
Michal Trunecka <mtruneck@redhat.com>
David Spurek <dspurek@redhat.com>

=back

=cut
