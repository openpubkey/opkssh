#!/bin/bash
# Script to test OpenSSH version detection in an Arch Linux container
# This validates the command used in main.go for detecting OpenSSH version on Arch-based systems

set -e  # Exit immediately if a command fails

echo "=== Starting Arch Linux container test ==="

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed or not in PATH. Please install Docker first."
    exit 1
fi

echo "=== Pulling Arch Linux ARM-compatible image ==="
docker pull menci/archlinuxarm:latest

echo "=== Running test in container ==="
docker run --rm --platform linux/arm64 menci/archlinuxarm:latest bash -c "
    echo \"Installing required packages...\"
    pacman -Sy --noconfirm --needed openssh sed awk

    echo \"=== Executing the OpenSSH version detection command ===\" 

    # The exact command from main.go - first defining the command string
    cmd=\"version=\\\$(/usr/bin/pacman -Qi openssh | /usr/bin/awk '/^Version/ {print \\\$3}' | /bin/sed -E 's/^([0-9]+\\\\.[0-9]+).*/\\\\1/'); /bin/echo \\\"OpenSSH_\\\$version\\\"\"
    echo \"Command to execute: \$cmd\"
    
    # Now execute it with /bin/sh -c just like in the Go code
    echo \"Output when executed with /bin/sh -c:\"
    /bin/sh -c \"\$cmd\"
"

echo "=== Test completed ==="
