#!/bin/bash

# 1.1.1.1 - Ensure mounting of cramfs filesystems is disabled (Scored)

# Ensure OS variable is set (passed from main script)
if [[ -z "$OS" ]]; then
    echo "ERROR: OS variable not set. Please run this script via the main CIS benchmark script."
    exit 1
fi

# Define modprobe.d directory
MODPROBE_DIR="/etc/modprobe.d"

# Check if cramfs is configured to be disabled
check_modprobe_config() {
    local os="$1"
    local config_file

    # Ubuntu typically uses *.conf files; Debian may use any file
    if [[ "$os" == "ubuntu" ]]; then
        config_file="$MODPROBE_DIR/*.conf"
    else
        config_file="$MODPROBE_DIR/*"
    fi

    if modprobe -n -v cramfs 2>&1 | grep -q "install /bin/true"; then
        echo "PASS: cramfs is configured to be disabled (install /bin/true found)"
        return 0
    elif modprobe -n -v cramfs 2>&1 | grep -q "FATAL: Module cramfs not found"; then
        echo "PASS: cramfs module is not available on $os"
        return 0
    else
        echo "FAIL: cramfs is not configured to be disabled on $os. Add 'install cramfs /bin/true' to $MODPROBE_DIR/cramfs.conf"
        return 1
    fi
}

# Check if cramfs is currently loaded
check_module_loaded() {
    local os="$1"
    if lsmod | grep -q "^cramfs"; then
        echo "FAIL: cramfs module is currently loaded on $os. Run 'modprobe -r cramfs' to unload."
        return 1
    else
        echo "PASS: cramfs module is not loaded on $os"
        return 0
    fi
}

# Run checks
check_modprobe_config "$OS" || exit 1
check_module_loaded "$OS" || exit 1

exit 0
