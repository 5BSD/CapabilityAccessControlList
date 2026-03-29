#!/bin/sh
#
# CACL Test Runner
#
# Run all tests and report results.
#

TESTS="
	test_add_self
	test_add
	test_remove
	test_remove_self
	test_clear
	test_exec
	test_fork
	test_socket
	test_socket_ops
	test_pipe_ops
	test_shm
	test_vnode
	test_multi
	test_errors
	test_unit
	test_ioctl
	test_threads
	test_edge
	test_comprehensive
	test_lock_query
	test_auto_cleanup
	test_timed
"

# Colors for output (use printf to interpret escapes)
RED=$(printf '\033[0;31m')
GREEN=$(printf '\033[0;32m')
YELLOW=$(printf '\033[0;33m')
NC=$(printf '\033[0m')

PASS=0
FAIL=0
SKIP=0

cd "$(dirname "$0")"

# Check if module is loaded
if [ ! -c /dev/cacl ]; then
	echo "${YELLOW}Warning: /dev/cacl not found. Module may not be loaded.${NC}"
	echo "Load the module with: sudo kldload ./cacl.ko"
	echo ""
fi

echo "========================================"
echo "         CACL Test Suite"
echo "========================================"
echo ""

for test in $TESTS; do
	if [ ! -x "./$test" ]; then
		echo "${YELLOW}SKIP${NC}: $test (not built)"
		SKIP=$((SKIP + 1))
		continue
	fi

	printf "Running %-20s ... " "$test"

	# Run test and capture output
	output=$(./"$test" 2>&1)
	ret=$?

	case $ret in
	0)
		echo "${GREEN}PASS${NC}"
		PASS=$((PASS + 1))
		;;
	77)
		echo "${YELLOW}SKIP${NC}"
		SKIP=$((SKIP + 1))
		;;
	*)
		echo "${RED}FAIL${NC} (exit code $ret)"
		echo "$output" | sed 's/^/    /'
		FAIL=$((FAIL + 1))
		;;
	esac
done

echo ""
echo "========================================"
echo "Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, ${YELLOW}$SKIP skipped${NC}"
echo "========================================"

if [ $FAIL -gt 0 ]; then
	exit 1
fi
exit 0
