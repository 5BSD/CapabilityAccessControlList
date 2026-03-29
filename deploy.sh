#!/bin/sh
#
# Deploy CACL module to a FreeBSD VM via SSH.
# Builds locally, copies binaries, loads module, and runs tests.
#
# Usage: ./deploy.sh <ip_address> [user] [--no-test]
#
# Options:
#   --no-test    Skip running tests after deployment
#

set -e

usage() {
    echo "Usage: $0 <ip_address> [user] [--no-test]"
    echo "  ip_address  - IP address of the FreeBSD VM"
    echo "  user        - SSH user (default: root)"
    echo "  --no-test   - Skip unload/load/test cycle (deploy only)"
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

IP=""
USER="root"
RUN_TESTS=1  # Run tests by default

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --no-test)
            RUN_TESTS=0
            ;;
        -*)
            echo "Unknown option: $arg"
            usage
            ;;
        *)
            if [ -z "$IP" ]; then
                IP="$arg"
            else
                USER="$arg"
            fi
            ;;
    esac
done

if [ -z "$IP" ]; then
    usage
fi

REMOTE_DIR="/root/cacl"

# Get absolute path to project root
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Building locally ==="
make -C "$SCRIPT_DIR" clean
make -C "$SCRIPT_DIR"
make -C "$SCRIPT_DIR/tests" clean
make -C "$SCRIPT_DIR/tests"

echo ""
echo "=== Deploying to ${USER}@${IP} ==="

ssh "${USER}@${IP}" "rm -rf ${REMOTE_DIR} && mkdir -p ${REMOTE_DIR}/tests"

scp -q "$SCRIPT_DIR/cacl.ko" "${USER}@${IP}:${REMOTE_DIR}/"

# Copy all test binaries
scp -q \
    "$SCRIPT_DIR/tests/test_add_self" \
    "$SCRIPT_DIR/tests/test_add" \
    "$SCRIPT_DIR/tests/test_remove" \
    "$SCRIPT_DIR/tests/test_remove_self" \
    "$SCRIPT_DIR/tests/test_clear" \
    "$SCRIPT_DIR/tests/test_exec" \
    "$SCRIPT_DIR/tests/test_fork" \
    "$SCRIPT_DIR/tests/test_socket" \
    "$SCRIPT_DIR/tests/test_socket_ops" \
    "$SCRIPT_DIR/tests/test_pipe_ops" \
    "$SCRIPT_DIR/tests/test_shm" \
    "$SCRIPT_DIR/tests/test_vnode" \
    "$SCRIPT_DIR/tests/test_multi" \
    "$SCRIPT_DIR/tests/test_errors" \
    "$SCRIPT_DIR/tests/test_unit" \
    "$SCRIPT_DIR/tests/test_ioctl" \
    "$SCRIPT_DIR/tests/test_threads" \
    "$SCRIPT_DIR/tests/test_edge" \
    "$SCRIPT_DIR/tests/test_comprehensive" \
    "$SCRIPT_DIR/tests/test_lock_query" \
    "$SCRIPT_DIR/tests/test_auto_cleanup" \
    "$SCRIPT_DIR/tests/test_timed" \
    "$SCRIPT_DIR/tests/test_helper" \
    "$SCRIPT_DIR/tests/run_tests.sh" \
    "${USER}@${IP}:${REMOTE_DIR}/tests/"

echo ""
echo "=== Deployment complete ==="

if [ $RUN_TESTS -eq 1 ]; then
    echo ""
    echo "=== Running tests on ${USER}@${IP} ==="
    echo ""

    # Unload old module (ignore errors), load new one, run tests, report
    ssh "${USER}@${IP}" "
        cd ${REMOTE_DIR}

        # Unload old module if loaded
        if kldstat -q -m cacl 2>/dev/null; then
            echo 'Unloading existing cacl module...'
            kldunload cacl || true
        fi

        # Load new module
        echo 'Loading cacl module...'
        kldload ./cacl.ko

        # Verify loaded
        if [ ! -c /dev/cacl ]; then
            echo 'ERROR: /dev/cacl not created after kldload'
            exit 1
        fi

        echo 'Module loaded successfully.'
        echo ''

        # Run tests
        cd tests
        ./run_tests.sh
        test_result=\$?

        # Unload module
        cd ..
        echo ''
        echo 'Unloading cacl module...'
        kldunload cacl

        exit \$test_result
    "

    echo ""
    echo "=== Test run complete ==="
else
    echo ""
    echo "Skipping tests (--no-test specified)."
    echo ""
    echo "To manually test on the VM:"
    echo "  ssh ${USER}@${IP}"
    echo "  cd ${REMOTE_DIR}"
    echo "  kldload ./cacl.ko"
    echo "  cd tests && ./run_tests.sh"
    echo "  kldunload cacl"
fi
