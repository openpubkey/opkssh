#!/bin/bash
# Script to test OpenSSH version detection in a SUSE Linux container
# This validates the command used in main.go for detecting OpenSSH version on SUSE-based systems

set -e  # Exit immediately if a command fails

echo "=== Starting SUSE Linux container test ==="

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed or not in PATH. Please install Docker first."
    exit 1
fi

echo "=== Pulling SUSE Linux image ==="
docker pull opensuse/leap:latest

echo "=== Running test in container ==="
docker run --rm opensuse/leap:latest bash -c "
    echo \"Installing required packages...\"
    zypper --non-interactive install openssh sed

    echo \"=== Executing the OpenSSH version detection command ===\" 

    # The exact command from main.go - first defining the command string
    cmd=\"version=\\\$(/usr/bin/rpm -q --qf \\\"%{VERSION}\\\\n\\\" openssh | /bin/sed -E 's/^([0-9]+\\\\.[0-9]+).*/\\\\1/'); /bin/echo \\\"OpenSSH_\\\$version\\\"\"
    echo \"Command to execute: \$cmd\"
    
    # Now execute it with /bin/sh -c just like in the Go code
    echo \"Output when executed with /bin/sh -c:\"
    /bin/sh -c \"\$cmd\"
"

echo "=== Test completed ==="
