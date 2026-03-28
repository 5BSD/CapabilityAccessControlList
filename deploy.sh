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
# Use /root instead of /tmp - /tmp is mounted nosuid which blocks
# MAC credential transitions needed for exec token change tests.
REMOTE_DIR="/root/cacl"

cd "$(dirname "$0")"

echo "=== Building locally ==="
make clean && make
cd tests && make clean && make && cd ..

echo ""
echo "=== Deploying to ${USER}@${IP} ==="

# Create remote directory and copy
ssh "${USER}@${IP}" "rm -rf ${REMOTE_DIR} && mkdir -p ${REMOTE_DIR}/tests"

scp -q \
    cacl.ko \
    "${USER}@${IP}:${REMOTE_DIR}/"

scp -q \
    tests/test_add_self \
    tests/test_add \
    tests/test_remove \
    tests/test_clear \
    tests/test_exec \
    tests/test_fork \
    tests/test_socket \
    tests/test_socket_ops \
    tests/test_pipe_ops \
    tests/test_shm \
    tests/test_vnode \
    tests/test_multi \
    tests/test_errors \
    tests/test_unit \
    tests/test_ioctl \
    tests/test_threads \
    tests/test_edge \
    tests/test_helper \
    tests/run_tests.sh \
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
