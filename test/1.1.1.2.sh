#!/bin/bash

# 1.1.1.2 - Ensure mounting of freevxfs filesystems is disabled (Scored)

# Ensure OS variable is set (passed from main script)
if [[ -z "$OS" ]]; then
    echo "ERROR: OS variable not set. Please run this script via the main CIS benchmark script."
    exit 1
fi

# Define modprobe.d directory
MODPROBE_DIR="/etc/modprobe.d"

# Check if freevxfs is configured to be disabled
check_modprobe_config() {
    local os="$1"
    local config_file

    # Ubuntu typically uses *.conf files; Debian may use any file
    if [[ "$os" == "ubuntu" ]]; then
        config_file="$MODPROBE_DIR/*.conf"
    else
        config_file="$MODPROBE_DIR/*"
    fi

    if modprobe -n -v freevxfs 2>&1 | grep -q "install /bin/true"; then
        echo "PASS: freevxfs is configured to be disabled (install /bin/true found)"
        return 0
    elif modprobe -n -v freevxfs 2>&1 | grep -q "FATAL: Module freevxfs not found"; then
        echo "PASS: freevxfs module is not available on $os"
        return 0
    else
        echo "FAIL: freevxfs is not configured to be disabled on $os. Add 'install freevxfs /bin/true' to $MODPROBE_DIR/freevxfs.conf"
        return 1
    fi
}

# Check if freevxfs is currently loaded
check_module_loaded() {
    local os="$1"
    if lsmod | grep -q "^freevxfs"; then
        echo "FAIL: freevxfs module is currently loaded on $os. Run 'modprobe -r freevxfs' to unload."
        return 1
    else
        echo "PASS: freevxfs module is not loaded on $os"
        return 0
    fi
}

# Run checks
check_modprobe_config "$OS" || exit 1
check_module_loaded "$OS" || exit 1

exit 0
