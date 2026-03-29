#!/bin/sh
#
# Deploy CACL module to a FreeBSD VM via SSH.
# Builds locally, copies binaries.
#
# Usage: ./deploy.sh <ip_address> [user]
#

set -e

if [ $# -lt 1 ]; then
    echo "Usage: $0 <ip_address> [user]"
    echo "  ip_address  - IP address of the FreeBSD VM"
    echo "  user        - SSH user (default: root)"
    exit 1
fi

IP="$1"
USER="${2:-root}"
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

scp -q \
    "$SCRIPT_DIR/tests/test_add_self" \
    "$SCRIPT_DIR/tests/test_add" \
    "$SCRIPT_DIR/tests/test_remove" \
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
    "$SCRIPT_DIR/tests/test_helper" \
    "$SCRIPT_DIR/tests/run_tests.sh" \
    "${USER}@${IP}:${REMOTE_DIR}/tests/"

echo ""
echo "=== Done ==="
echo ""
echo "On the VM:"
echo "  ssh ${USER}@${IP}"
echo "  cd ${REMOTE_DIR}"
echo "  kldload ./cacl.ko"
echo "  cd tests && ./run_tests.sh"
echo "  kldunload cacl"
