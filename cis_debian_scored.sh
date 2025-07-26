```bash
#!/bin/bash

# Print start message
echo "Starting CIS Debian Linux Scored Benchmark Audit at $(date '+%Y-%m-%d %H:%M:%S')"

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root" >&2
    exit 1
fi

# Initialize variables
TABLE_ROWS_FILE=$(mktemp 2>/dev/null || { echo "Error: Failed to create temporary file" >&2; exit 1; })
PASS_COUNT=0
FAIL_COUNT=0
DEBUG_LOG="cis_debug.log"
touch "$DEBUG_LOG" 2>/dev/null || { echo "Error: Cannot create $DEBUG_LOG" >&2; exit 1; }

# Clean up temporary file on exit
trap 'rm -f "$TABLE_ROWS_FILE"' EXIT

# Function to log debug messages
log_debug() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$DEBUG_LOG" 2>/dev/null || echo "Warning: Failed to write to $DEBUG_LOG" >&2
}

# Check for required commands
check_dependencies() {
    local missing=0
    for cmd in mountpoint stat grep dpkg systemctl mktemp; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "Error: Required command '$cmd' is missing" >&2
            log_debug "Missing command: $cmd"
            missing=1
        fi
    done
    if [ "$missing" -eq 1 ]; then
        echo "Error: Install missing dependencies (e.g., apt install coreutils dpkg util-linux systemd)" >&2
        exit 1
    fi
    log_debug "All dependencies verified"
    echo "Dependencies check passed"
}

# Function to add result to HTML table rows and update counters
add_result() {
    local finding_id="$1"
    local issue_name="$2"
    local status="$3"
    local risk_rating="$4"
    local fix_type="$5"
    local remediation="$6"
    local status_class=$(echo "$status" | tr '[:upper:]' '[:lower:]')
    local risk_class=$(echo "$risk_rating" | tr '[:upper:]' '[:lower:]')

    log_debug "Processing finding $finding_id"

    # Validate inputs
    if [ -z "$finding_id" ] || [ -z "$issue_name" ] || [ -z "$status" ] || [ -z "$risk_rating" ] || [ -z "$fix_type" ] || [ -z "$remediation" ]; then
        log_debug "Error: Invalid input for finding $finding_id"
        echo "Error: Invalid input for finding $finding_id" >&2
        return 1
    fi

    # Sanitize inputs
    issue_name=$(echo "$issue_name" | sed 's/[[:cntrl:]]//g; s/"/\\"/g; s/`/\\`/g; s/'\''/\\'\''/g')
    remediation=$(echo "$remediation" | sed 's/[[:cntrl:]]//g; s/"/\\"/g; s/`/\\`/g; s/'\''/\\'\''/g')
    issue_name=$(echo "$issue_name" | sed 's/&/\&/g; s/</\</g; s/>/\>/g; s/"/\"/g; s/'\''/\'/g')
    remediation=$(echo "$remediation" | sed 's/&/\&/g; s/</\</g; s/>/\>/g; s/"/\"/g; s/'\''/\'/g')

    # Write to temporary file using heredoc
    cat << EOF >> "$TABLE_ROWS_FILE" 2>>"$DEBUG_LOG"
<tr class="$risk_class"><td>$finding_id</td><td>$issue_name</td><td class="$status_class">$status</td><td>$risk_rating</td><td>$fix_type</td><td>$remediation</td></tr>
EOF
    if [ $? -ne 0 ]; then
        log_debug "Failed to write result for $finding_id"
        echo "Error: Failed to write result for $finding_id" >&2
        return 1
    fi

    if [ "$status" = "Pass" ]; then
        ((PASS_COUNT++))
    else
        ((FAIL_COUNT++))
    fi
    log_debug "Added result for $finding_id: Status=$status"
}

# Generate HTML report with pie chart
generate_html_report() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    log_debug "Generating HTML report"

    if [ ! -s "$TABLE_ROWS_FILE" ]; then
        log_debug "Error: TABLE_ROWS_FILE is empty or missing"
        echo "Error: No results to include in the report. Check $DEBUG_LOG for details." >&2
        exit 1
    fi

    cat << EOF > cis_debian_scored_report.html 2>>"$DEBUG_LOG"
<!DOCTYPE html>
<html>
<head>
    <title>CIS Debian Linux Scored Benchmark Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .pass { color: green; }
        .fail { color: red; }
        .critical { background-color: #ffcccc; }
        .high { background-color: #ff9999; }
        .medium { background-color: #ffcc99; }
        .low { background-color: #ccffcc; }
        #chart-container { width: 400px; margin: 20px auto; }
    </style>
</head>
<body>
    <h1>CIS Debian Linux Scored Benchmark Report</h1>
    <p>Generated on: $timestamp</p>
    <table>
        <tr>
            <th>Finding ID</th>
            <th>Issue Name</th>
            <th>Status</th>
            <th>Risk Rating</th>
            <th>Fix Type</th>
            <th>Remediation</th>
        </tr>
        $(cat "$TABLE_ROWS_FILE")
    </table>
    <div id="chart-container">
        <canvas id="cis"></canvas>
    </div>
    <script>
        const ctx = document.getElementById('cis').getContext('2d');
        const complianceChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: ['Pass', 'Fail'],
                datasets: [{
                    data: [$PASS_COUNT, $FAIL_COUNT],
                    backgroundColor: ['#36a2eb', '#ff6384'],
                    borderColor: ['#ffffff', '#fff'],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'top' },
                    title: { display: true, text: 'CIS Scored Compliance Status' }
                }
            }
        });
    </script>
</body>
</html>
EOF
    if [ $? -eq 0 ]; then
        echo "Report generated: cis_debian_scored_report.html"
        log_debug "Report generated successfully"
    else
        log_debug "Failed to generate HTML report"
        echo "Error: Failed to generate HTML report. Check $DEBUG_LOG for details." >&2
        exit 1
    fi
}

# Scored Checks (75 from CIS Debian Linux 12 Benchmark v1.0.1)
check_tmp_partition() {
    log_debug "Running check_tmp_partition"
    if mountpoint -q /tmp 2>>"$DEBUG_LOG"; then
        add_result "1.1.2.1" "Ensure /tmp is configured as a separate partition" "Pass" "High" "Involved" "Configure /tmp as a separate partition in /etc/fstab with nosuid, noexec, nodev."
    else
        add_result "1.1.2.1" "Ensure /tmp is configured as a separate partition" "Fail" "High" "Involved" "Configure /tmp/fstab with nosuid, noexec, nodev."
    fi
}

check_tmp_nodev() {
    log_debug "Checking /tmp nodev option"
    if mount | grep -q '/tmp.*nodev' 2>>"$DEBUG_LOG"; then
        add_result "1.1.2.2" "Ensure nodev option set on /tmp partition" "Pass" "Medium" "Quick" "Add nodev to /tmp in /etc/fstab and remount."
    else
        add_result "1.1.2.2" "Ensure nodev option set on /tmp partition" "Fail" "Medium" "Quick" "Add nodev to /tmp in /etc/fstab and remount."
    fi
}

check_tmp_nosuid() {
    log_debug "Checking /tmp nosuid option"
    if mount | grep -q '/tmp.*nosuid' 2>>"$DEBUG_LOG"; then
        add_result "1.1.2.3" "Ensure nosuid option set on /tmp partition" "Pass" "Medium" "Quick" "Add nosuid to /tmp in /etc/fstab and remount."
    else
        add_result "1.1.2.3" "Ensure nosuid option set on /tmp partition" "Fail" "Medium" "Quick" "Add nosuid to /tmp in /etc/fstab and remount."
    fi
}

check_tmp_noexec() {
    log_debug "Checking /tmp noexec option"
    if mount | grep -q '/tmp.*noexec' 2>>"$DEBUG_LOG"; then
        add_result "1.1.2.4" "Ensure noexec option set on /tmp partition" "Pass" "Medium" "Quick" "Add noexec to /tmp in /etc/fstab and remount."
    else
        add_result "1.1.2.4" "Ensure noexec option set on /tmp partition" "Fail" "Medium" "Quick" "Add noexec to /tmp in /etc/fstab and remount."
    fi
}

check_var_partition() {
    log_debug "Running check_var_partition"
    if mountpoint -q /var 2>>"$DEBUG_LOG"; then
        add_result "1.1.3.1" "Ensure /var is configured as a separate partition" "Pass" "High" "Involved" "Configure /var as a separate partition in /etc/fstab."
    else
        add_result "1.1.3.1" "Ensure /var is configured as a separate partition" "Fail" "High" "Involved" "Configure /var/etc/fstab."
    fi
}

check_var_tmp() {
    log_debug "Running check_var_tmp"
    if mountpoint -q /var/tmp 2>>"$DEBUG_LOG"; then
        add_result "1.1.4.1" "Ensure separate partition exists for /var/tmp" "Pass" "High" /tmp" "Configure /var/tmp as a separate partition in /etc/fstab."
    else
        add_result "1.1.4.1" "Ensure separate partition exists for /var/tmp" "Fail" "High" /tmp" "Configure /var/tmp as a separate partition/fstab."
    fi
}

check_var_tmp_nodev() {
    log_debug "Checking /var/tmp nodev option"
    if mount | grep -q '/var/tmp.*nodev' 2>>"$DEBUG_LOG"; then
        add_result "1.1.4.2" "Ensure nodev option set on /var/tmp partition" "Pass" "Medium" "Quick" "Add nodev to /var/tmp in /etc/fstab and remount."
    else
        add_result "1.1.4.2" "Ensure nodev option set on /var/tmp partition" "Fail" "Medium" "Quick" "Add nodev to /var/tmp in /etc/fstab and remount."
    fi
}

check_var_tmp_nosuid() {
    log_debug "Checking /var/tmp nosuid option"
    if mount | grep -q '/var/tmp.*nosuid' 2>>"$DEBUG_LOG"; then
        add_result "1.1.4.3" "Ensure nosuid option set on /var/tmp partition" "Pass" "Medium" "Quick" "Add nosuid to /var/tmp in /etc/fstab and remount."
    else
        add_result "1.1.4.3" "Ensure nosuid option set on /var/tmp partition" "Fail" "Medium" "Quick" "Add nosuid to /var/tmp in /var/tmp/fstab and remount."
    fi
}

check_var_tmp_noexec() {
    log_debug "Checking /var/tmp noexec option"
    if mount | grep -q '/var/tmp.*noexec' 2>>"$DEBUG_LOG"; then
        add_result "1.1.4.4" "Ensure noexec option set /var/tmp partition" "Pass" on"Medium" "Quick" /tmp" "Add noexec to /var/tmp in /etc/fstab and remount."
    else
        add_result "1.1.4.4" "Ensure noexec option /var/tmp partition" "Fail" on /tmp in /tmp/fstab and remount."
    fi
}

check_var_log_partition() {
    log_debug "Running check_var_log_partition"
    if mountpoint -q /var/log 2>>"$DEBUG_LOG"; then
        add_result "1.1.5.1" "Ensure /var/log is configured as a separate partition" "Pass" "High" "Involved" "Configure /var/log as a separate partition in /etc/fstab."
    else
        add_result "1.1.5.1" "Ensure /var/log is configured as a separate partition" "Fail" "High" "Involved" "Configure /var/log/etc/fstab."
    fi
}

check_var_log_audit_partition() {
    log_debug "Running check_var_log_audit_partition"
    if mountpoint -q /var/log/audit 2>>"$DEBUG_LOG"; then
        add_result "1.1.6.1" "Ensure /var/log/audit is configured as a separate partition" "Pass" "High" "Involved" "Configure /var/log/audit as a separate partition in /etc/fstab."
    else
        add_result "1.1.6.1" "Ensure /var/log/audit is configured as a separate partition" "Fail" "High" "Involved" "Configure /var/log/audit/etc/fstab."
    fi
}

check_home_partition() {
    log_debug "Running check_home_partition"
    if mountpoint -q /home 2>>"$DEBUG_LOG"; then
        add_result "1.1.7.1" "Ensure separate partition exists for /home" "Pass" "High" "Involved" "Configure /home as a separate partition in /etc/fstab."
    else
        add_result "1.1.7.1" "Ensure separate partition exists for /home" "Fail" "High" "Involved" "Configure /home/etc/fstab."
    fi
}

check_home_nodev() {
    log_debug "Checking /home nodev option"
    if mount | grep -q '/home.*nodev' 2>>"$DEBUG_LOG"; then
        add_result "1.1.7.2" "Ensure nodev option set on /home partition" "Pass" "Medium" "Quick" "Add nodev to /home in /etc/fstab and remount."
    else
        add_result "1.1.7.2" "Ensure nodev option set on /home partition" "Fail" "Medium" "Quick" "Add nodev to /home in /etc/fstab and remount."
    fi
}

check_dev_shm_nodev() {
    log_debug "Checking /dev/shm nodev option"
    if mount | grep -q '/dev/shm.*nodev' 2>>"$DEBUG_LOG"; then
        add_result "1.1.8.1" "Ensure nodev option set on /dev/shm partition" "Pass" "Medium" "Quick" "Add nodev to /dev/shm in /etc/fstab and remount."
    else
        add_result "1.1.8.1" "Ensure nodev option set on /dev/shm partition" "Fail" "Medium" "Quick" "Add nodev to /dev/shm in /etc/fstab and remount."
    fi
}

check_dev_shm_nosuid() {
    log_debug "Checking /dev/shm nosuid option"
    if mount | grep -q '/dev/shm.*nosuid' 2>>"$DEBUG_LOG"; then
        add_result "1.1.8.2" "Ensure nosuid option set on /dev/shm partition" "Pass" "Medium" "Quick" "Add nosuid to /dev/shm in /etc/fstab and remount."
    else
        add_result "1.1.8.2" "Ensure nosuid option set on /dev/shm partition" "Fail" "Medium" "Quick" "Add nosuid to /dev/shm in /etc/fstab and remount."
    fi
}

check_dev_shm_noexec() {
    log_debug "Checking /dev/shm noexec option"
    if mount | grep -q '/dev/shm.*noexec' 2>>"$DEBUG_LOG"; then
        add_result "1.1.8.3" "Ensure noexec option set on /dev/shm partition" "Pass" "Medium" "Quick" "Add noexec to /dev/shm in /etc/fstab and remount."
    else
        add_result "1.1.8.3" "Ensure noexec option set on /dev/shm partition" "Fail" "Medium" "Quick" "Add noexec to /dev/shm in /etc/fstab and remount."
    fi
}

check_removable_media_nodev() {
    log_debug "Checking removable media nodev option"
    if grep -q "nodev" /etc/fstab | grep -q "/media" 2>>"$DEBUG_LOG"; then
        add_result "1.1.9.1" "Ensure nodev option set on removable media partitions" "Pass" "Medium" "Quick" "Add nodev to removable media in /etc/fstab."
    else
        add_result "1.1.9.1" "Ensure nodev option set on removable media partitions" "Fail" "Medium" "Quick" "Add nodev to removable media in /etc/fstab."
    fi
}

check_removable_media_nosuid() {
    log_debug "Checking removable media nosuid option"
    if grep -q "nosuid" /etc/fstab | grep -q "/media" 2>>"$DEBUG_LOG"; then
        add_result "1.1.9.2" "Ensure nosuid option set on removable media partitions" "Pass" "Medium" "Quick" "Add nosuid to removable media in /etc/fstab."
    else
        add_result "1.1.9.2" "Ensure nosuid option set on removable media partitions" "Fail" "Medium" "Quick" "Add nosuid to removable media in /etc/fstab."
    fi
}

check_removable_media_noexec() {
    log_debug "Checking removable media noexec option"
    if grep -q "noexec" /etc/fstab | grep -q "/media" 2>>"$DEBUG_LOG"; then
        add_result "1.1.9.3" "Ensure noexec option set on removable media partitions" "Pass" "Medium" "Quick" "Add noexec to removable media in /etc/fstab."
    else
        add_result "1.1.9.3" "Ensure noexec option set on removable media partitions" "Fail" "Medium" "Quick" "Add noexec to removable media in /etc/fstab."
    fi
}

check_sticky_bit() {
    log_debug "Checking sticky bit on world-writable directories"
    if [ -z "$(find / -type d -perm -0002 -a ! -perm -1000 2>>"$DEBUG_LOG")" ]; then
        add_result "1.1.22" "Ensure sticky bit is set on all world-writable directories" "Pass" "High" "Quick" "Run: find / -type d -perm -0002 -exec chmod +t {} \;"
    else
        add_result "1.1.22" "Ensure sticky bit is set on all world-writable directories" "Fail" "High" "Quick" "Run: find / -type d -perm -0002 -exec chmod +t {} \;"
    fi
}

check_automounting() {
    log_debug "Checking automounting status"
    if ! systemctl is-enabled autofs >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "1.1.23" "Ensure automounting is disabled" "Pass" "Medium" "Quick" "Run: systemctl disable autofs"
    else
        add_result "1.1.23" "Ensure automounting is disabled" "Fail" "Medium" "Quick" "Run: systemctl disable autofs"
    fi
}

check_bootloader_password() {
    log_debug "Checking bootloader password"
    if [ -f /boot/grub/grub.cfg ] && grep -q "set superusers=" /boot/grub/grub.cfg 2>>"$DEBUG_LOG"; then
        add_result "1.4.1" "Ensure bootloader password is set" "Pass" "High" "Quick" "Set a password for GRUB: grub-mkpasswd-pbkdf2"
    else
        add_result "1.4.1" "Ensure bootloader password is set" "Fail" "High" "Quick" "Set a password for GRUB: grub-mkpasswd-pbkdf2"
    fi
}

check_bootloader_permissions() {
    log_debug "Checking bootloader permissions"
    local perms owner group
    perms=$(stat -c "%a" /boot/grub/grub.cfg 2>>"$DEBUG_LOG")
    owner=$(stat -c "%U" /boot/grub/grub.cfg 2>>"$DEBUG_LOG")
    group=$(stat -c "%G" /boot/grub/grub.cfg 2>>"$DEBUG_LOG")
    if [ "$perms" = "600" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        add_result "1.4.2" "Ensure permissions on bootloader config are configured" "Pass" "High" "Quick" "Run: chmod 600 /boot/grub/grub.cfg; chown root:root /boot/grub/grub.cfg"
    else
        add_result "1.4.2" "Ensure permissions on bootloader config are configured" "Fail" "High" "Quick" "Run: chmod 600 /boot/grub/grub.cfg; chown root:root /boot/grub/grub.cfg"
    fi
}

check_aslr() {
    log_debug "Checking ASLR configuration"
    if sysctl kernel.randomize_va_space | grep -q "2" 2>>"$DEBUG_LOG"; then
        add_result "1.5.1" "Ensure address space layout randomization (ASLR) is enabled" "Pass" "Medium" "Quick" "Add \'kernel.randomize_va_space = 2\' to /etc/sysctl.conf."
    else
        add_result "1.5.1" "Ensure address space layout randomization (ASLR) is enabled" "Fail" "Medium" "Quick" "Add \'kernel.randomize_va_space = 2\' to /etc/sysctl.conf."
    fi
}

check_prelink() {
    log_debug "Checking prelink installation"
    if ! dpkg -s prelink >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "1.5.2" "Ensure prelink is not installed" "Pass" "Medium" "Quick" "Run: apt remove prelink"
    else
        add_result "1.5.2" "Ensure prelink is not installed" "Fail" "Medium" "Quick" "Run: apt remove prelink"
    fi
}

check_apparmor_enabled() {
    log_debug "Checking AppArmor status"
    if dpkg -s apparmor >/dev/null 2>>"$DEBUG_LOG" && systemctl is-enabled apparmor >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "1.6.1.1" "Ensure AppArmor is enabled" "Pass" "High" "Quick" "Run: apt install apparmor; systemctl enable apparmor"
    else
        add_result "1.6.1.1" "Ensure AppArmor is enabled" "Fail" "High" "Quick" "Run: apt install apparmor; systemctl enable apparmor"
    fi
}

check_apparmor_profiles() {
    log_debug "Checking AppArmor profiles"
    if aa-status | grep -q "profiles are in enforce mode" 2>>"$DEBUG_LOG"; then
        add_result "1.6.1.2" "Ensure all AppArmor profiles are in enforce or complain mode" "Pass" "High" "Quick" "Run: aa-enforce /etc/apparmor.d/*"
    else
        add_result "1.6.1.2" "Ensure all AppArmor profiles are in enforce or complain mode" "Fail" "High" "Quick" "Run: aa-enforce /etc/apparmor.d/*"
    fi
}

check_telnet_server() {
    log_debug "Checking telnet server installation"
    if ! dpkg -s telnetd >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "2.2.1" "Ensure telnet server is not installed" "Pass" "High" "Quick" "Run: apt remove telnetd"
    else
        add_result "2.2.1" "Ensure telnet server is not installed" "Fail" "High" "Quick" "Run: apt remove telnetd"
    fi
}

check_ftp_server() {
    log_debug "Checking FTP server installation"
    if ! dpkg -s vsftpd >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "2.2.2" "Ensure FTP server is not installed" "Pass" "High" "Quick" "Run: apt remove vsftpd"
    else
        add_result "2.2.2" "Ensure FTP server is not installed" "Fail" "High" "Quick" "Run: apt remove vsftpd"
    fi
}

check_nfs_server() {
    log_debug "Checking NFS server installation"
    if ! dpkg -s nfs-kernel-server >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "2.2.3" "Ensure NFS server is not installed" "Pass" "Medium" "Quick" "Run: apt remove nfs-kernel-server"
    else
        add_result "2.2.3" "Ensure NFS server is not installed" "Fail" "Medium" "Quick" "Run: apt remove nfs-kernel-server"
    fi
}

check_dns_server() {
    log_debug "Checking DNS server installation"
    if ! dpkg -s bind9 >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "2.2.4" "Ensure DNS server is not installed" "Pass" "Medium" "Quick" "Run: apt remove bind9"
    else
        add_result "2.2.4" "Ensure DNS server is not installed" "Fail" "Medium" "Quick" "Run: apt remove bind9"
    fi
}

check_mta_local_only() {
    log_debug "Checking MTA configuration"
    if ! systemctl is-active postfix >/dev/null 2>>"$DEBUG_LOG" || grep -q "inet_interfaces = loopback-only" /etc/postfix/main.cf 2>>"$DEBUG_LOG"; then
        add_result "2.2.5" "Ensure mail transfer agent is configured for local-only" "Pass" "Medium" "Quick" "Edit /etc/postfix/main.cf and set 'inet_interfaces = loopback-only'. Restart postfix."
    else
        add_result "2.2.5" "Ensure mail transfer agent is configured for local-only" "Fail" "Medium" "Quick" "Edit /etc/postfix/main.cf and set 'inet_interfaces = loopback-only'. Restart postfix."
    fi
}

check_chrony_configured() {
    log_debug "Checking chrony configuration"
    if dpkg -s chrony >/dev/null 2>>"$DEBUG_LOG" && systemctl is-enabled chrony >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "2.2.6" "Ensure chrony is configured" "Pass" "Medium" "Quick" "Run: apt install chrony; systemctl enable chrony; systemctl start chrony"
    else
        add_result "2.2.6" "Ensure chrony is configured" "Fail" "Medium" "Quick" "Run: apt install chrony; systemctl enable chrony; systemctl start chrony"
    fi
}

check_x_window_system() {
    log_debug "Checking X Window System installation"
    if ! dpkg -s xserver-xorg >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "2.2.7" "Ensure X Window System is not installed" "Pass" "Medium" "Quick" "Run: apt remove xserver-xorg"
    else
        add_result "2.2.7" "Ensure X Window System is not installed" "Fail" "Medium" "Quick" "Run: apt remove xserver-xorg"
    fi
}

check_avahi_server() {
    log_debug "Checking Avahi server installation"
    if ! dpkg -s avahi-daemon >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "2.2.8" "Ensure Avahi server is not installed" "Pass" "Medium" "Quick" "Run: apt remove avahi-daemon"
    else
        add_result "2.2.8" "Ensure Avahi server is not installed" "Fail" "Medium" "Quick" "Run: apt remove avahi-daemon"
    fi
}

check_cups() {
    log_debug "Checking CUPS installation"
    if ! dpkg -s cups >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "2.2.9" "Ensure CUPS is not installed" "Pass" "Medium" "Quick" "Run: apt remove cups"
    else
        add_result "2.2.9" "Ensure CUPS is not installed" "Fail" "Medium" "Quick" "Run: apt remove cups"
    fi
}

check_dhcp_server() {
    log_debug "Checking DHCP server installation"
    if ! dpkg -s isc-dhcp-server >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "2.2.10" "Ensure DHCP server is not installed" "Pass" "Medium" "Quick" "Run: apt remove isc-dhcp-server"
    else
        add_result "2.2.10" "Ensure DHCP server is not installed" "Fail" "Medium" "Quick" "Run: apt remove isc-dhcp-server"
    fi
}

check_ldap_server() {
    log_debug "Checking LDAP server installation"
    if ! dpkg -s slapd >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "2.2.11" "Ensure LDAP server is not installed" "Pass" "Medium" "Quick" "Run: apt remove slapd"
    else
        add_result "2.2.11" "Ensure LDAP server is not installed" "Fail" "Medium" "Quick" "Run: apt remove slapd"
    fi
}

check_snmp_server() {
    log_debug "Checking SNMP server installation"
    if ! dpkg -s snmpd >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "2.2.12" "Ensure SNMP server is not installed" "Pass" "Medium" "Quick" "Run: apt remove snmpd"
    else
        add_result "2.2.12" "Ensure SNMP server is not installed" "Fail" "Medium" "Quick" "Run: apt remove snmpd"
    fi
}

check_samba() {
    log_debug "Checking Samba installation"
    if ! dpkg -s samba >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "2.2.13" "Ensure Samba is not installed" "Pass" "Medium" "Quick" "Run: apt remove samba"
    else
        add_result "2.2.13" "Ensure Samba is not installed" "Fail" "Medium" "Quick" "Run: apt remove samba"
    fi
}

check_http_server() {
    log_debug "Checking HTTP server installation"
    if ! dpkg -s apache2 >/dev/null 2>>"$DEBUG_LOG" && ! dpkg -s nginx >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "2.2.14" "Ensure HTTP server is not installed" "Pass" "Medium" "Quick" "Run: apt remove apache2 nginx"
    else
        add_result "2.2.14" "Ensure HTTP server is not installed" "Fail" "Medium" "Quick" "Run: apt remove apache2 nginx"
    fi
}

check_imap_pop3_server() {
    log_debug "Checking IMAP/POP3 server installation"
    if ! dpkg -s dovecot-imapd >/dev/null 2>>"$DEBUG_LOG" && ! dpkg -s dovecot-pop3d >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "2.2.15" "Ensure IMAP and POP3 server is not installed" "Pass" "Medium" "Quick" "Run: apt remove dovecot-imapd dovecot-pop3d"
    else
        add_result "2.2.15" "Ensure IMAP and POP3 server is not installed" "Fail" "Medium" "Quick" "Run: apt remove dovecot-imapd dovecot-pop3d"
    fi
}

check_nis_server() {
    log_debug "Checking NIS server installation"
    if ! dpkg -s nis >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "2.2.16" "Ensure NIS server is not installed" "Pass" "Medium" "Quick" "Run: apt remove nis"
    else
        add_result "2.2.16" "Ensure NIS server is not installed" "Fail" "Medium" "Quick" "Run: apt remove nis"
    fi
}

check_rsh_server() {
    log_debug "Checking rsh server installation"
    if ! dpkg -s rsh-server >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "2.2.17" "Ensure rsh server is not installed" "Pass" "High" "Quick" "Run: apt remove rsh-server"
    else
        add_result "2.2.17" "Ensure rsh server is not installed" "Fail" "High" "Quick" "Run: apt remove rsh-server"
    fi
}

check_nis_client() {
    log_debug "Checking NIS client installation"
    if ! dpkg -s nis >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "2.2.18" "Ensure NIS client is not installed" "Pass" "Medium" "Quick" "Run: apt remove nis"
    else
        add_result "2.2.18" "Ensure NIS client is not installed" "Fail" "Medium" "Quick" "Run: apt remove nis"
    fi
}

check_rsh_client() {
    log_debug "Checking rsh client installation"
    if ! dpkg -s rsh-client >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "Pass" "High" "Quick" "Run: apt remove rsh-client"
    else
        add_result "Fail" "High" "Quick" "Run: apt remove rsh-client"
    fi
}

check_tftp_client() {
    log_debug "Checking TFTP client installation"
    if ! dpkg -s tftp >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "2.2.20" "Ensure TFTP client is not installed" "Pass" "Medium" "Quick" "Run: apt remove tftp"
    else
        add_result "2.2.20" "Ensure TFTP client is not installed" "Fail" "Medium" "Quick" "Run: apt remove tftp"
    fi
}

check_cron_enabled() {
    log_debug "Checking cron service"
    if systemctl is-enabled cron >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "3.5.1" "Ensure cron daemon is enabled" "Pass" "Medium" "Quick" "Run: systemctl enable cron; systemctl start cron"
    else
        add_result "3.5.1" "Ensure cron daemon is disabled" "Fail" "Medium" "Quick" "Run: systemctl enable cron; systemctl start cron"
    fi
}

check_auditd_service() {
    log_debug "Checking auditd service"
    if systemctl is-enabled auditd >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "4.1.1.1" "Ensure auditd service is enabled" "Pass" "Critical" "Quick" "Run: apt install auditd; systemctl enable auditd; systemctl start auditd"
    else
        add_result "4.1.1.1" "Ensure auditd service is enabled" "Fail" "Critical" "Quick" "Run: apt install auditd; systemctl enable auditd; systemctl start auditd"
    fi
}

check_rsyslog_enabled() {
    log_debug "Checking rsyslog service"
    if systemctl is-enabled rsyslog >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "4.2.1.1" "Ensure rsyslog service is enabled" "Pass" "Medium" "Quick" "Run: apt install rsyslog; systemctl enable rsyslog; systemctl start rsyslog"
    else
        add_result "4.2.1.1" "Ensure rsyslog service is disabled" "Fail" "Medium" "Quick" "Run: apt install rsyslog; systemctl enable rsyslog; systemctl start rsyslog"
    fi
}

check_logrotate() {
    log_debug "Checking logrotate"
    if dpkg -s logrotate >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "Pass" "Medium" "Quick" "Run: apt install logrotate"
    else
        add_result() "Fail" "Medium" "Quick" "Run: apt install logrotate"
    fi
}

check_crontab_permissions() {
    log_debug "Checking /etc/crontab permissions"
    local perms owner group
    perms=$(stat -c "%a" /etc/crontab 2>>"$DEBUG_LOG")
    owner=$(stat -c "%U" /etc/crontab 2>>"$DEBUG_LOG")
    group=$(stat -c "%G" /etc/crontab 2>>"$DEBUG_LOG")
    if [ "$perms" = "600" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        add_result "5.1.1" "Ensure permissions on /etc/crontab are configured" "Pass" "Medium" "Quick" "Run: chmod 600 /etc/crontab; chown root:root /etc/crontab"
    else
        add_result "5.1.1" "Ensure permissions on /etc/crontab are configured" "Fail" "Medium" "Quick" "Run: chmod 600 /etc/crontab; chown root:root /etc/crontab"
    fi
}

check_cron_hourly_permissions() {
    log_debug "Checking /etc/cron.hourly permissions"
    local perms owner group
    perms=$(stat -c "%a" /etc/cron.hourly 2>>"$DEBUG_LOG")
    owner=$(stat -c "%U" /etc/cron.hourly 2>>"$DEBUG_LOG")
    group=$(stat -c "%G" /etc/cron.hourly 2>>"$DEBUG_LOG")
    if [ "$perms" = "700" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        add_result "5.1.2" "Ensure permissions on /etc/cron.hourly are configured" "Pass" "Medium" "Quick" "Run: chmod 700 /etc/cron.hourly; chown root:root /etc/cron.hourly"
    else
        add_result "5.1.2" "Ensure permissions on /etc/cron.hourly are configured" "Fail" "Medium" "Quick" "Run: chmod 700 /etc/cron.hourly; chown root:root /etc/cron.hourly"
    fi
}

check_cron_daily_permissions() {
    log_debug "Checking /etc/cron.daily permissions"
    local perms owner group
    perms=$(stat -c "%a" /etc/cron.daily 2>>"$DEBUG_LOG")
    owner=$(stat -c "%U" /etc/cron.daily 2>>"$DEBUG_LOG")
    group=$(stat -c "%G" /etc/cron.daily 2>>"$DEBUG_LOG")
    if [ "$perms" = "700" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        add_result "5.1.3" "Ensure permissions on /etc/cron.daily are configured" "Pass" "Medium" "Quick" "Run: chmod 700 /etc/cron.daily; chown root:root /etc/cron.daily"
    else
        add_result "5.1.3" "Ensure permissions on /etc/cron.daily are configured" "Fail" "Medium" "Quick" "Run: chmod 700 /etc/cron.daily; chown root:root /etc/cron.daily"
    fi
}

check_cron_weekly_permissions() {
    log_debug "Checking /etc/cron.weekly permissions"
    local perms owner group
    perms=$(stat -c "%a" /etc/cron.weekly 2>>"$DEBUG_LOG")
    owner=$(stat -c "%U" /etc/cron.weekly 2>>"$DEBUG_LOG")
    group=$(stat -c "%G" /etc/cron.weekly 2>>"$DEBUG_LOG")
    if [ "$perms" = "700" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        add_result "5.1.4" "Ensure permissions on /etc/cron.weekly are configured" "Pass" "Medium" "Quick" "Run: chmod 700 /etc/cron.weekly; chown root:root /etc/cron.weekly"
    else
        add_result "5.1.4" "Ensure permissions on /etc/cron.weekly are configured" "Fail" "Medium" "Quick" "Run: chmod 700 /etc/cron.weekly; chown root:root /etc/cron.weekly"
    fi
}

check_cron_monthly_permissions() {
    log_debug "Checking /etc/cron.monthly permissions"
    local perms owner group
    perms=$(stat -c "%a" /etc/cron.monthly 2>>"$DEBUG_LOG")
    owner=$(stat -c "%U" /etc/cron.monthly 2>>"$DEBUG_LOG")
    group=$(stat -c "%G" /etc/cron.monthly 2>>"$DEBUG_LOG")
    if [ "$perms" = "700" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        add_result "5.1.5" "Ensure permissions on /etc/cron.monthly are configured" "Pass" "Medium" "Quick" "Run: chmod 700 /etc/cron.monthly; chown root:root /etc/cron.monthly"
    else
        add_result "5.1.5" "Ensure permissions on /etc/cron.monthly are configured" "Fail" "Medium" "Quick" "Run: chmod 700 /etc/cron.monthly; chown root:root /etc/cron.monthly"
    fi
}

check_passwd_permissions() {
    log_debug "Checking /etc/passwd permissions"
    local perms owner group
    perms=$(stat -c "%a" /etc/passwd 2>>"$DEBUG_LOG")
    owner=$(stat -c "%U" /etc/passwd 2>>"$DEBUG_LOG")
    group=$(stat -c "%G" /%etc/passwd 2>>"$DEBUG_LOG")
    if [ "$perms" = "644" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        add_result "5.4.1" "Ensure permissions on /etc/passwd are configured" "Pass" "Medium" "Quick" "Run: chmod 644 /etc/passwd; chown root:root /etc/passwd"
    else
        add_result "5.4.1" "Ensure permissions on /etc/passwd are configured" "Fail" "Medium" "Quick" "Run: chmod 644 /etc/passwd; chown root:root /etc/passwd"
    fi
}

check_shadow_permissions() {
    log_debug "Checking /etc/shadow permissions"
    local perms owner group
    perms=$(stat -c "%a" /etc/shadow 2>>"$DEBUG_LOG")
    owner=$(stat -c "%U" /etc/shadow 2>>"$DEBUG_LOG")
    group=$(stat -c "%G" /etc/shadow 2>>"$DEBUG_LOG")
    if [ "$perms" = "640" ] && [ "$owner" = "root" ] && [ "$group" = "shadow" ]; then
        add_result "5.4.2" "Ensure permissions on /etc/shadow are configured" "Pass" "High" "Quick" "Run: chmod 640 /etc/shadow; chown root:shadow /etc/shadow"
    else
        add_result "5.4.2" "Ensure permissions on /etc/shadow are configured" "Fail" "High" "Quick" "Run: chmod 640 /etc/shadow; chown root:shadow /etc/shadow"
    fi
}

check_group_permissions() {
    log_debug "Checking /etc/group permissions"
    local perms owner group
    perms=$(stat -c "%a" /etc/group 2>>"$DEBUG_LOG")
    owner=$(stat -c "%U" /etc/group 2>>"$DEBUG_LOG")
    group=$(stat -c "%G" /etc/group 2>>"$DEBUG_LOG")
    if [ "$perms" = "644" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        add_result "5.4.3" "Ensure permissions on /etc/group are configured" "Pass" "Medium" "Quick" "Run: chmod 644 /etc/group; chown root:root /etc/group"
    else
        add_result "5.4.3" "Ensure permissions on /etc/group are configured" "Fail" "Medium" "Quick" "Run: chmod 644 /etc/group; chown root:root /etc/group"
    fi
}

check_gshadow_permissions() {
    log_debug "Checking /etc/gshadow permissions"
    local perms owner group
    perms=$(stat -c "%a" /etc/gshadow 2>>"$DEBUG_LOG")
    owner=$(stat -c "%U" /etc/gshadow 2>>"$DEBUG_LOG")
    group=$(stat -c "%G" /etc/gshadow 2>>"$DEBUG_LOG")
    if [ "$perms" = "640" ] && [ "$owner" = "root" ] && [ "$group" = "shadow" ]; then
        add_result "5.4.4" "Ensure permissions on /etc/gshadow are configured" "Pass" "High" "Quick" "Run: chmod 640 /etc/gshadow; chown root:shadow /etc/gshadow"
    else
        add_result "5.4.4" "Ensure permissions on /etc/gshadow are configured" "Fail" "High" "Quick" "Run: chmod 640 /etc/gshadow; chown root:shadow /etc/gshadow"
    fi
}

check_ssh_config_permissions() {
    log_debug "Checking /etc/ssh/sshd_config permissions"
    local perms owner group
    perms=$(stat -c "%a" /etc/ssh/sshd_config 2>>"$DEBUG_LOG")
    owner=$(stat -c "%U" /etc/ssh/sshd_config 2>>"$DEBUG_LOG")
    group=$(stat -c "%G" /etc/ssh/sshd_config 2>>"$DEBUG_LOG")
    if [ "$perms" = "600" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        add_result "5.2.1" "Ensure permissions on /etc/ssh/sshd_config are configured" "Pass" "Medium" "Quick" "Run: chmod 600 /etc/ssh/sshd_config; chown root:root /etc/ssh/sshd_config"
    else
        add_result "5.2.1" "Ensure permissions on /etc/ssh/sshd_config are configured" "Fail" "Medium" "Quick" "Run: chmod 600 /etc/ssh/sshd_config; chown root:root /etc/ssh/sshd_config"
    fi
}

check_ssh_protocol() {
    log_debug "Checking SSH protocol"
    if grep -q "^Protocol\s+2" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
        add_result "5.2.2" "Ensure SSH Protocol is set to 2" "Pass" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'Protocol 2'. Restart sshd."
    else
        add_result "5.2.2" "Ensure SSH Protocol is set to 2" "Fail" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'Protocol 2'. Restart sshd."
    fi
}

check_ssh_loglevel() {
    log_debug "Checking SSH log level"
    if grep -q "^LogLevel\s+INFO\s*" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
        add_result "5.2.3" "Ensure SSH LogLevel is set to INFO" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'LogLevel INFO'. Restart sshd."
    else
        add_result "5.2.3" "Ensure SSH LogLevel is set to INFO" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'LogLevel INFO'. Restart sshd."
    fi
}

check_ssh_maxauthtries() {
    log_debug "Checking SSH MaxAuthTries"
    if grep -q "^MaxAuthTries\s+[1-4]\s*" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
        add_result "5.2.4" "Ensure SSH MaxAuthTries is set to 4 or less" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'MaxAuthTries 4'. Restart sshd."
    else
        add_result "5.2.4" "Ensure SSH MaxAuthTries is set to 4 or less" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'MaxAuthTries 4'. Restart sshd."
    fi
}

check_ssh_permitrootlogin() {
    log_debug "Checking SSH PermitRootLogin"
    if grep -q "^PermitRootLogin\s+no\s*$" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
        add_result "5.2.5" "Ensure SSH PermitRootLogin is disabled" "Pass" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'PermitRootLogin no'. Restart sshd."
    else
        add_result "5.2.5" "Ensure SSH PermitRootLogin is disabled" "Fail" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'PermitRootLogin no'. Restart sshd."
    fi
}

check_ssh_permitemptypasswords() {
    log_debug "Checking SSH PermitEmptyPasswords"
    if grep -q "^PermitEmptyPasswords\s+no\s*$" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
        add_result "5.2.6" "Ensure SSH PermitEmptyPasswords is disabled" "Pass" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'PermitEmptyPasswords no'. Restart sshd."
    else
        add_result "5.2.6" "Ensure SSH PermitEmptyPasswords is disabled" "Fail" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'PermitEmptyPasswords no'. Restart sshd."
    fi
}

check_ssh_ignoreuserknownhosts() {
    log_debug "Checking SSH IgnoreUserKnownHosts"
    if grep -q "^IgnoreUserKnownHosts\s+yes\s*$" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
        add_result "5.2.7" "Ensure SSH IgnoreUserKnownHosts is enabled" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'IgnoreUserKnownHosts yes'. Restart sshd."
    else
        add_result "5.2.7" "Ensure SSH IgnoreUserKnownHosts is enabled" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'IgnoreUserKnownHosts yes'. Restart sshd."
    fi
}

check_ssh_hostbasedauth() {
    log_debug "Checking SSH HostbasedAuthentication"
    if grep -q "^HostbasedAuthentication\s+no\s*$" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
        add_result "5.2.8" "Ensure SSH HostbasedAuthentication is disabled" "Pass" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'HostbasedAuthentication no'. Restart sshd."
    else
        add_result "5.2.8" "Ensure SSH HostbasedAuthentication is disabled" "Fail" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'HostbasedAuthentication no'. Restart sshd."
    fi
}

check_ssh_permituserenv() {
    log_debug "Checking SSH PermitUserEnvironment"
    if grep -q "^PermitUserEnvironment\s+no\s*$" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
        add_result "5.2.9" "Ensure SSH PermitUserEnvironment is disabled" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'PermitUserEnvironment no'. Restart sshd."
    else
        add_result "5.2.9" "Ensure SSH PermitUserEnvironment is disabled" "Fail" /etc/ssh/sshd_config and set 'PermitUserEnvironment no'. Restart sshd."
    fi
}

check_ssh_ignore_rhosts() {
    log_debug "Checking SSH IgnoreRhosts"
    if grep -q "^IgnoreRhosts\s+yes\s+no\s*$" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
        add_result "Pass" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'IgnoreRhosts yes'. Restart sshd."
    else
        add_result() "Fail" "High" "Quick" /etc/ssh/sshd_config and set 'IgnoreRhosts no'. Restart sshd."
    fi
}

check_ssh_maxstartups() {
    log_debug "Checking SSH MaxStartups"
    if grep -q "^MaxStartups\s+10:30:60\s*$" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
        add_result "5.2.11" "Ensure SSH MaxStartups is configured" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'MaxStartups 10:30:60'. Restart sshd."
    else
        add_result "5.2.11" "Ensure SSH MaxStartups is configured" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'MaxStartups 10:30:60'. Restart sshd."
    fi
}

check_ssh_clientaliveinterval() {
    log_debug "Checking SSH ClientAliveInterval"
    if grep -q "^ClientAliveInterval\s+300\s*$" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
        add_result "5.2.12" "Ensure SSH ClientAliveInterval is configured" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'ClientAliveInterval 300'. Restart sshd."
    else
        add_result "5.2.12" "Ensure SSH ClientAliveInterval is configured" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'ClientAliveInterval 300'. Restart sshd."
    fi
}

check_ssh_clientalivecountmax() {
    log_debug "Checking SSH ClientAliveCountMax"
    if grep -q "^ClientAliveCountMax\s+3\s*$" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
        add_result "5.2.13" "Ensure SSH ClientAliveCountMax is configured" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'ClientAliveCountMax 3'. Restart sshd."
    else
        add_result "5.2.13" "Ensure SSH ClientAliveCountMax is configured" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'ClientAliveCountMax 3'. Restart sshd."
    fi
}

check_ssh_logingracetime() {
    log_debug "Checking SSH LoginGraceTime"
    if grep -q "^LoginGraceTime\s+60\s*$" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
        add_result "5.2.14" "Ensure SSH LoginGraceTime is set to one minute or less" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'LoginGraceTime 60'. Restart sshd."
    else
        add_result "5.2.14" "Ensure SSH LoginGraceTime is set to one minute or less" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'LoginGraceTime 60'. Restart sshd."
    fi
}

check_ssh_allowtcpforwarding() {
    log_debug "Checking SSH AllowTcpForwarding"
    if grep -q "^AllowTcpForwarding\s+no\s*$" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
        add_result "5.2.15" "Ensure SSH AllowTcpForwarding is disabled" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'AllowTcpForwarding no'. Restart sshd."
    else
        add_result "5.2.15" "Ensure SSH AllowTcpForwarding is disabled" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'AllowTcpForwarding no'. Restart sshd."
    fi
}

check_password_expiration() {
    log_debug "Checking password expiration"
    if grep -q "^PASS_MAX_DAYS\s\+365\s*$" /etc/login.defs 2>>"$DEBUG_LOG"; then
        add_result "5.3.1" "Ensure password expiration is 365 days or less" "Pass" "Medium" "Quick" "Edit /etc/login.defs and set 'PASS_MAX_DAYS 365'."
    else
        add_result "5.3.1" "Ensure password expiration is 365 days or less" "Fail" "Medium" "Quick" "Edit /etc/login.defs and set 'PASS_MAX_DAYS 365'."
    fi
}

check_password_min_days() {
    log_debug "Checking minimum password days"
    if grep -q "^PASS_MIN_DAYS\s\+7\s*$" /etc/login.defs 2>>"$DEBUG_LOG"; then
        add_result "5.3.2" "Ensure minimum days between password changes is 7 or more" "Pass" "Medium" "Quick" "Edit /etc/login.defs and set 'PASS_MIN_DAYS 7'."
    else
        add_result "5.3.2" "Ensure minimum days between password changes is 7 or more" "Fail" "Medium" "Quick" "Edit /etc/login.defs and set 'PASS_MIN_DAYS 7'."
    fi
}

check_password_warn_age() {
    log_debug "Checking password warning age"
    if grep -q "^PASS_WARN_AGE\s\+7\s*$" /etc/login.defs 2>>"$DEBUG_LOG"; then
        add_result "5.3.3" "Ensure password expiration warning days is 7 or more" "Pass" "Medium" "Quick" "Edit /etc/login.defs and set 'PASS_WARN_AGE 7'."
    else
        add_result "5.3.3" "Ensure password expiration warning days is 7 or more" "Fail" "Medium" "Quick" "Edit /etc/login.defs and set 'PASS_WARN_AGE 7'."
    fi
}

check_inactive_password_lock() {
    log_debug "Checking inactive password lock"
    if [ "$(useradd -D | grep INACTIVE | cut -d= -f2 2>>"$DEBUG_LOG")" -le 30 ]; then
        add_result "5.3.4" "Ensure inactive password lock is 30 days or less" "Pass" "Medium" "Quick" "Run: useradd -D -f 30"
    else
        add_result "5.3.4" "Ensure inactive password lock is 30 days or less" "Fail" "Medium" "Quick" "Run: useradd -D -f 30"
    fi
}

# Run dependency checks
check_dependencies

# Execute all checks
echo "Running 75 CIS scored checks..."
check_tmp_partition
check_tmp_nodev
check_tmp_nosuid
check_tmp_noexec
check_var_partition
check_var_tmp
check_var_tmp_nodev
check_var_tmp_nosuid
check_var_tmp_noexec
check_var_log_partition
check_var_log_audit
check_home_partition
check_home_nodev
check_dev_shm_nodev
check_dev_shm_nosuid
check_dev_shm_noexec
check_removable_media_nodev
check_removable_media_nosuid
check_removable_media_noexec
check_sticky_bit
check_automounting
check_bootloader_password
check_bootloader_permissions
check_aslr
check_prelink
check_apparmor_enabled
check_apparmor_profiles
check_telnet_server
check_ftp_server
check_nfs_server
check_dns_server
check_mta_local_only
check_chrony_configured
check_x_window_system
check_avahi_server
check_cups
check_dhcp_server
check_ldap_server
check_snmp_server
check_samba
check_http_server
check_imap_pop3_server
check_nis_server
check_rsh_server
check_nis_client
check_rsh_client
check_tftp_client
check_cron_enabled
check_auditd_service
check_rsyslog_enabled
check_logrotate
check_crontab_permissions
check_cron_hourly_permissions
check_cron_daily_permissions
check_cron_weekly_permissions
check_cron_monthly_permissions
check_passwd_permissions
check_shadow_permissions
check_group_permissions
check_gshadow_permissions
check_ssh_config_permissions
check_ssh_protocol
check_ssh_loglevel
check_ssh_maxauthtries
check_ssh_permitrootlogin
check_ssh_permitemptypasswords
check_ssh_ignoreuserknownhosts
check_ssh_hostbasedauth
check_ssh_permituserenv
check_ssh_ignore_rhosts
check_ssh_maxstartups
check_ssh_clientaliveinterval
check_ssh_clientalivecountmax
check_ssh_logingracetime
check_ssh_allowtcpforwarding
check_password_expiration
check_password_min_days
check_password_warn_age
check_inactive_password_lock

# Generate report
echo "Finalizing report..."
generate_html_report
echo "Script execution completed at $(date '+%Y-%m-%d %H:%M:%S')"
```
