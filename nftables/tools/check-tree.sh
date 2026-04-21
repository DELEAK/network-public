#!/bin/bash -e

# Preform various consistency checks of the source tree.

unset LANGUAGE
export LANG=C
export LC_ALL=C

die() {
	printf '%s\n' "$*"
	exit 1
}

array_contains() {
	local needle="$1"
	local a
	shift
	for a; do
		[ "$a" = "$needle" ] && return 0
	done
	return 1
}

cd "$(dirname "$0")/.."

EXIT_CODE=0

msg_err() {
	printf "ERR:  %s\n" "$*"
	EXIT_CODE=1
}

msg_warn() {
	printf "WARN: %s\n" "$*"
}

##############################################################################

check_shell_dumps() {
	local TEST="$1"
	local base="$(basename "$TEST")"
	local dir="$(dirname "$TEST")"
	local has_nft=0
	local has_jnft=0
	local has_nodump=0
	local nft_name
	local nodump_name

	if [ ! -d "$dir/dumps/" ] ; then
		msg_err "\"$TEST\" has no \"$dir/dumps/\" directory"
		return 0
	fi

	nft_name="$dir/dumps/$base.nft"
	jnft_name="$dir/dumps/$base.json-nft"
	nodump_name="$dir/dumps/$base.nodump"

	[ -f "$nft_name" ] && has_nft=1
	[ -f "$jnft_name" ] && has_jnft=1
	[ -f "$nodump_name" ] && has_nodump=1

	if [ "$has_nft" != 1 -a "$has_nodump" != 1 ] ; then
		msg_err "\"$TEST\" has no \"$dir/dumps/$base.{nft,nodump}\" file"
	elif [ "$has_nft" == 1 -a "$has_nodump" == 1 ] ; then
		msg_err "\"$TEST\" has both \"$dir/dumps/$base.{nft,nodump}\" files"
	elif [ "$has_nodump" == 1 -a -s "$nodump_name" ] ; then
		msg_err "\"$TEST\" has a non-empty \"$dir/dumps/$base.nodump\" file"
	fi
	if [ "$has_jnft" = 1 -a "$has_nft" != 1 ] ; then
		msg_err "\"$TEST\" has a JSON dump file \"$jnft_name\" but lacks a dump \"$nft_name\""
	fi
	if [ "$has_nft" = 1 -a "$has_jnft" != 1 ] ; then
		# it's currently known that `nft -j --check` cannot parse all dumped rulesets.
		# Accept having no JSON dump file.
		#
		# This should be fixed. Currently this is only a warning.
		msg_warn "\"$TEST\" has a dump file \"$nft_name\" but lacks a JSON dump \"$jnft_name\""
	fi

	if [ "$has_jnft" = 1 ] && command -v jq &>/dev/null ; then
		if ! jq empty < "$jnft_name" &>/dev/null ; then
			msg_err "\"$TEST\" has a JSON dump file \"$jnft_name\" that does not validate with \`jq empty < \"$jnft_name\"\`"
		fi
	fi
}

SHELL_TESTS=( $(find "tests/shell/testcases/" -type f -executable | sort) )

if [ "${#SHELL_TESTS[@]}" -eq 0 ] ; then
	msg_err "No executable tests under \"tests/shell/testcases/\" found"
fi
for t in "${SHELL_TESTS[@]}" ; do
	check_shell_dumps "$t"
	if ! ( head -n 1 "$t" | grep -q '^#!/bin/bash\( -e\)\?$' ) ; then
		# Currently all tests only use bash as shebang. That also
		# works with `./tests/shell/run-tests.sh -x`.
		#
		# We could allow other shebangs, but for now there is no need.
		# Unless you have a good reason, create a bash script.
		msg_err "$t should use either \"#!/bin/bash\" or \"#!/bin/bash -e\" as shebang"
	fi
done

##############################################################################

SHELL_TESTS2=( $(./tests/shell/run-tests.sh --list-tests) )
if [ "${SHELL_TESTS[*]}" != "${SHELL_TESTS2[*]}" ] ; then
	msg_err "\`./tests/shell/run-tests.sh --list-tests\` does not list the expected tests"
fi

##############################################################################
#
F=( $(find tests/shell/testcases/ -type f | grep '^tests/shell/testcases/[^/]\+/dumps/[^/]\+\.\(json-nft\|nft\|nodump\)$' -v | sort) )
IGNORED_FILES=( tests/shell/testcases/bogons/nft-f/* tests/shell/testcases/bogons/nft-j-f/* )
for f in "${F[@]}" ; do
	if ! array_contains "$f" "${SHELL_TESTS[@]}" "${IGNORED_FILES[@]}" ; then
		msg_err "Unexpected file \"$f\""
	fi
done

##############################################################################

FILES=( $(find "tests/shell/testcases/" -type f | sed -n 's#\(tests/shell/testcases\(/.*\)\?/\)dumps/\(.*\)\.\(nft\|nodump\)$#\0#p' | sort) )

for f in "${FILES[@]}" ; do
	f2="$(echo "$f" | sed -n 's#\(tests/shell/testcases\(/.*\)\?/\)dumps/\(.*\)\.\(nft\|nodump\)$#\1\3#p')"
	if ! array_contains "$f2" "${SHELL_TESTS[@]}" ; then
		msg_err "\"$f\" has no test \"$f2\""
	fi
done

##############################################################################

exit "$EXIT_CODE"
