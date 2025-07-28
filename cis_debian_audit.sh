#!/bin/bash

# Initialize debug log
DEBUG_LOG="cis_debian_debug.log"
: > "$DEBUG_LOG"
echo "[DEBUG] Script started at $(date '+%Y-%m-%d %H:%M:%S')" >> "$DEBUG_LOG"

# Check for required commands
REQUIRED_CMDS=("grep" "sed" "cat" "mktemp" "rm" "date")
MISSING_CMDS=()
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>>"$DEBUG_LOG"; then
        MISSING_CMDS+=("$cmd")
    fi
done
if [ ${#MISSING_CMDS[@]} -ne 0 ]; then
    echo "[ERROR] Missing required commands: ${MISSING_CMDS[*]}" | tee -a "$DEBUG_LOG"
    echo "[WARNING] Some checks may fail due to missing commands" | tee -a "$DEBUG_LOG"
fi

# Check if running in a Linux environment
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "[WARNING] Not running in a Linux environment (detected: $(uname -s)). Results may be inaccurate." | tee -a "$DEBUG_LOG"
fi

# Initialize temporary file for HTML table rows
TABLE_ROWS_FILE=$(mktemp 2>>"$DEBUG_LOG")
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to create temporary file for table rows" | tee -a "$DEBUG_LOG"
    exit 1
fi
echo "[DEBUG] Temporary file for table rows: $TABLE_ROWS_FILE" >> "$DEBUG_LOG"

# Function to escape HTML special characters
html_escape() {
    local input="$1"
    printf "%s" "$input" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'\''/\&apos;/g' 2>>"$DEBUG_LOG"
}

# Function to add result directly to HTML table rows
add_result() {
    local finding_id="$1"
    local issue_name="$2"
    local status="$3"
    local risk_rating="$4"
    local fix_type="$5"
    local remediation="$6"
    local status_class=$(echo "$status" | tr '[:upper:]' '[:lower:]')
    local risk_class=$(echo "$risk_rating" | tr '[:upper:]' '[:lower:]')
    # Escape special characters for HTML
    issue_name=$(html_escape "$issue_name")
    remediation=$(html_escape "$remediation")
    echo "[DEBUG] Adding result: $finding_id, $issue_name, $status" >> "$DEBUG_LOG"
    # Use printf for robust HTML output
    printf "<tr class=\"%s\"><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" \
        "$risk_class" "$finding_id" "$issue_name" "$status_class" "$status" "$risk_rating" "$fix_type" "$remediation" >> "$TABLE_ROWS_FILE" 2>>"$DEBUG_LOG"
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to write to $TABLE_ROWS_FILE" | tee -a "$DEBUG_LOG"
    fi
}

# Function to check if a command is available
check_command() {
    local cmd="$1"
    if command -v "$cmd" >/dev/null 2>>"$DEBUG_LOG"; then
        return 0
    else
        echo "[DEBUG] Command $cmd not found, skipping related check" >> "$DEBUG_LOG"
        return 1
    fi
}

# Check 1: Ensure /tmp is configured as a separate partition
check_tmp_partition() {
    echo "[DEBUG] Checking /tmp partition" >> "$DEBUG_LOG"
    if check_command "mountpoint"; then
        if mountpoint -q /tmp 2>>"$DEBUG_LOG"; then
            add_result "1.1.1.1" "Ensure /tmp is configured as a separate partition" "Pass" "High" "Involved" "Configure /tmp as a separate partition in /etc/fstab with options like nosuid, noexec, nodev."
        else
            add_result "1.1.1.1" "Ensure /tmp is configured as a separate partition" "Fail" "High" "Involved" "Configure /tmp as a separate partition in /etc/fstab with options like nosuid, noexec, nodev."
        fi
    else
        add_result "1.1.1.1" "Ensure /tmp is configured as a separate partition" "Skipped" "High" "Involved" "Cannot check: mountpoint command not available."
    fi
}

# Check 2: Ensure nodev option set on /tmp partition
check_tmp_nodev() {
    echo "[DEBUG] Checking nodev on /tmp" >> "$DEBUG_LOG"
    if check_command "mount"; then
        if mount | grep /tmp | grep -q nodev 2>>"$DEBUG_LOG"; then
            add_result "1.1.1.2" "Ensure nodev option set on /tmp partition" "Pass" "Medium" "Quick" "Add nodev option to /tmp in /etc/fstab and remount."
        else
            add_result "1.1.1.2" "Ensure nodev option set on /tmp partition" "Fail" "Medium" "Quick" "Add nodev option to /tmp in /etc/fstab and remount."
        fi
    else
        add_result "1.1.1.2" "Ensure nodev option set on /tmp partition" "Skipped" "Medium" "Quick" "Cannot check: mount command not available."
    fi
}

# Check 3: Ensure nosuid option set on /tmp partition
check_tmp_nosuid() {
    echo "[DEBUG] Checking nosuid on /tmp" >> "$DEBUG_LOG"
    if check_command "mount"; then
        if mount | grep /tmp | grep -q nosuid 2>>"$DEBUG_LOG"; then
            add_result "1.1.1.3" "Ensure nosuid option set on /tmp partition" "Pass" "Medium" "Quick" "Add nosuid option to /tmp in /etc/fstab and remount."
        else
            add_result "1.1.1.3" "Ensure nosuid option set on /tmp partition" "Fail" "Medium" "Quick" "Add nosuid option to /tmp in /etc/fstab and remount."
        fi
    else
        add_result "1.1.1.3" "Ensure nosuid option set on /tmp partition" "Skipped" "Medium" "Quick" "Cannot check: mount command not available."
    fi
}

# Check 4: Ensure noexec option set on /tmp partition
check_tmp_noexec() {
    echo "[DEBUG] Checking noexec on /tmp" >> "$DEBUG_LOG"
    if check_command "mount"; then
        if mount | grep /tmp | grep -q noexec 2>>"$DEBUG_LOG"; then
            add_result "1.1.1.4" "Ensure noexec option set on /tmp partition" "Pass" "Medium" "Quick" "Add noexec option to /tmp in /etc/fstab and remount."
        else
            add_result "1.1.1.4" "Ensure noexec option set on /tmp partition" "Fail" "Medium" "Quick" "Add noexec option to /tmp in /etc/fstab and remount."
        fi
    else
        add_result "1.1.1.4" "Ensure noexec option set on /tmp partition" "Skipped" "Medium" "Quick" "Cannot check: mount command not available."
    fi
}

# Check 5: Ensure /var is a separate partition
check_var_partition() {
    echo "[DEBUG] Checking /var partition" >> "$DEBUG_LOG"
    if check_command "mountpoint"; then
        if mountpoint -q /var 2>>"$DEBUG_LOG"; then
            add_result "1.1.2.1" "Ensure /var is configured as a separate partition" "Pass" "High" "Involved" "Configure /var as a separate partition in /etc/fstab."
        else
            add_result "1.1.2.1" "Ensure /var is configured as a separate partition" "Fail" "High" "Involved" "Configure /var as a separate partition in /etc/fstab."
        fi
    else
        add_result "1.1.2.1" "Ensure /var is configured as a separate partition" "Skipped" "High" "Involved" "Cannot check: mountpoint command not available."
    fi
}

# Check 6: Ensure /var/log is a separate partition
check_var_log_partition() {
    echo "[DEBUG] Checking /var/log partition" >> "$DEBUG_LOG"
    if check_command "mountpoint"; then
        if mountpoint -q /var/log 2>>"$DEBUG_LOG"; then
            add_result "1.1.3.1" "Ensure /var/log is configured as a separate partition" "Pass" "High" "Involved" "Configure /var/log as a separate partition in /etc/fstab."
        else
            add_result "1.1.3.1" "Ensure /var/log is configured as a separate partition" "Fail" "High" "Involved" "Configure /var/log as a separate partition in /etc/fstab."
        fi
    else
        add_result "1.1.3.1" "Ensure /var/log is configured as a separate partition" "Skipped" "High" "Involved" "Cannot check: mountpoint command not available."
    fi
}

# Check 7: Ensure permissions on /etc/ssh/sshd_config are configured
check_ssh_config_permissions() {
    echo "[DEBUG] Checking /etc/ssh/sshd_config permissions" >> "$DEBUG_LOG"
    if check_command "stat" && [ -f /etc/ssh/sshd_config ]; then
        local perms owner group
        perms=$(stat -c "%a" /etc/ssh/sshd_config 2>>"$DEBUG_LOG")
        owner=$(stat -c "%U" /etc/ssh/sshd_config 2>>"$DEBUG_LOG")
        group=$(stat -c "%G" /etc/ssh/sshd_config 2>>"$DEBUG_LOG")
        if [ "$perms" = "600" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
            add_result "5.2.1" "Ensure permissions on /etc/ssh/sshd_config are configured" "Pass" "Medium" "Quick" "Run: chmod 600 /etc/ssh/sshd_config; chown root:root /etc/ssh/sshd_config"
        else
            add_result "5.2.1" "Ensure permissions on /etc/ssh/sshd_config are configured" "Fail" "Medium" "Quick" "Run: chmod 600 /etc/ssh/sshd_config; chown root:root /etc/ssh/sshd_config"
        fi
    else
        add_result "5.2.1" "Ensure permissions on /etc/ssh/sshd_config are configured" "Skipped" "Medium" "Quick" "Cannot check: stat command or /etc/ssh/sshd_config not available."
    fi
}

# Check 8: Ensure SSH Protocol is set to 2
check_ssh_protocol() {
    echo "[DEBUG] Checking SSH Protocol" >> "$DEBUG_LOG"
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^Protocol 2" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
            add_result "5.2.2" "Ensure SSH Protocol is set to 2" "Pass" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'Protocol 2'. Restart sshd: systemctl restart sshd"
        else
            add_result "5.2.2" "Ensure SSH Protocol is set to 2" "Fail" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'Protocol 2'. Restart sshd: systemctl restart sshd"
        fi
    else
        add_result "5.2.2" "Ensure SSH Protocol is set to 2" "Skipped" "High" "Quick" "Cannot check: /etc/ssh/sshd_config not available."
    fi
}

# Check 9: Ensure SSH LogLevel is set to INFO
check_ssh_loglevel() {
    echo "[DEBUG] Checking SSH LogLevel" >> "$DEBUG_LOG"
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^LogLevel INFO" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
            add_result "5.2.3" "Ensure SSH LogLevel is set to INFO" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'LogLevel INFO'. Restart sshd."
        else
            add_result "5.2.3" "Ensure SSH LogLevel is set to INFO" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'LogLevel INFO'. Restart sshd."
        fi
    else
        add_result "5.2.3" "Ensure SSH LogLevel is set to INFO" "Skipped" "Medium" "Quick" "Cannot check: /etc/ssh/sshd_config not available."
    fi
}

# Check 10: Ensure SSH MaxAuthTries is set to 4 or less
check_ssh_maxauthtries() {
    echo "[DEBUG] Checking SSH MaxAuthTries" >> "$DEBUG_LOG"
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^MaxAuthTries [1-4]" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
            add_result "5.2.4" "Ensure SSH MaxAuthTries is set to 4 or less" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'MaxAuthTries 4'. Restart sshd."
        else
            add_result "5.2.4" "Ensure SSH MaxAuthTries is set to 4 or less" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'MaxAuthTries 4'. Restart sshd."
        fi
    else
        add_result "5.2.4" "Ensure SSH MaxAuthTries is set to 4 or less" "Skipped" "Medium" "Quick" "Cannot check: /etc/ssh/sshd_config not available."
    fi
}

# Check 11: Ensure SSH PermitRootLogin is disabled
check_ssh_permitrootlogin() {
    echo "[DEBUG] Checking SSH PermitRootLogin" >> "$DEBUG_LOG"
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
            add_result "5.2.5" "Ensure SSH PermitRootLogin is disabled" "Pass" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'PermitRootLogin no'. Restart sshd."
        else
            add_result "5.2.5" "Ensure SSH PermitRootLogin is disabled" "Fail" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'PermitRootLogin no'. Restart sshd."
        fi
    else
        add_result "5.2.5" "Ensure SSH PermitRootLogin is disabled" "Skipped" "High" "Quick" "Cannot check: /etc/ssh/sshd_config not available."
    fi
}

# Check 12: Ensure SSH PermitEmptyPasswords is disabled
check_ssh_permitemptypasswords() {
    echo "[DEBUG] Checking SSH PermitEmptyPasswords" >> "$DEBUG_LOG"
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^PermitEmptyPasswords no" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
            add_result "5.2.6" "Ensure SSH PermitEmptyPasswords is disabled" "Pass" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'PermitEmptyPasswords no'. Restart sshd."
        else
            add_result "5.2.6" "Ensure SSH PermitEmptyPasswords is disabled" "Fail" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'PermitEmptyPasswords no'. Restart sshd."
        fi
    else
        add_result "5.2.6" "Ensure SSH PermitEmptyPasswords is disabled" "Skipped" "High" "Quick" "Cannot check: /etc/ssh/sshd_config not available."
    fi
}

# Check 13: Ensure package manager repositories are configured
check_apt_repos() {
    echo "[DEBUG] Checking APT repositories" >> "$DEBUG_LOG"
    if check_command "apt"; then
        if apt update >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "3.1.2" "Ensure package manager repositories are configured" "Pass" "Low" "Planned" "Configure valid repositories in /etc/apt/sources.list and ensure they are accessible."
        else
            add_result "3.1.2" "Ensure package manager repositories are configured" "Fail" "Low" "Planned" "Configure valid repositories in /etc/apt/sources.list and ensure they are accessible."
        fi
    else
        add_result "3.1.2" "Ensure package manager repositories are configured" "Skipped" "Low" "Planned" "Cannot check: apt command not available."
    fi
}

# Check 14: Ensure auditd service is enabled
check_auditd_service() {
    echo "[DEBUG] Checking auditd service" >> "$DEBUG_LOG"
    if check_command "systemctl"; then
        if systemctl is-enabled auditd >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "4.1.1" "Ensure auditd service is enabled" "Pass" "Critical" "Quick" "Run: apt install auditd; systemctl enable auditd; systemctl start auditd"
        else
            add_result "4.1.1" "Ensure auditd service is enabled" "Fail" "Critical" "Quick" "Run: apt install auditd; systemctl enable auditd; systemctl start auditd"
        fi
    else
        add_result "4.1.1" "Ensure auditd service is enabled" "Skipped" "Critical" "Quick" "Cannot check: systemctl command not available."
    fi
}

# Check 15: Ensure permissions on /etc/passwd are configured
check_passwd_permissions() {
    echo "[DEBUG] Checking /etc/passwd permissions" >> "$DEBUG_LOG"
    if check_command "stat" && [ -f /etc/passwd ]; then
        local perms owner group
        perms=$(stat -c "%a" /etc/passwd 2>>"$DEBUG_LOG")
        owner=$(stat -c "%U" /etc/passwd 2>>"$DEBUG_LOG")
        group=$(stat -c "%G" /etc/passwd 2>>"$DEBUG_LOG")
        if [ "$perms" = "644" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
            add_result "5.4.1" "Ensure permissions on /etc/passwd are configured" "Pass" "Medium" "Quick" "Run: chmod 644 /etc/passwd; chown root:root /etc/passwd"
        else
            add_result "5.4.1" "Ensure permissions on /etc/passwd are configured" "Fail" "Medium" "Quick" "Run: chmod 644 /etc/passwd; chown root:root /etc/passwd"
        fi
    else
        add_result "5.4.1" "Ensure permissions on /etc/passwd are configured" "Skipped" "Medium" "Quick" "Cannot check: stat command or /etc/passwd not available."
    fi
}

# Check 16: Ensure permissions on /etc/shadow are configured
check_shadow_permissions() {
    echo "[DEBUG] Checking /etc/shadow permissions" >> "$DEBUG_LOG"
    if check_command "stat" && [ -f /etc/shadow ]; then
        local perms owner group
        perms=$(stat -c "%a" /etc/shadow 2>>"$DEBUG_LOG")
        owner=$(stat -c "%U" /etc/shadow 2>>"$DEBUG_LOG")
        group=$(stat -c "%G" /etc/shadow 2>>"$DEBUG_LOG")
        if [ "$perms" = "640" ] && [ "$owner" = "root" ] && [ "$group" = "shadow" ]; then
            add_result "5.4.2" "Ensure permissions on /etc/shadow are configured" "Pass" "High" "Quick" "Run: chmod 640 /etc/shadow; chown root:shadow /etc/shadow"
        else
            add_result "5.4.2" "Ensure permissions on /etc/shadow are configured" "Fail" "High" "Quick" "Run: chmod 640 /etc/shadow; chown root:shadow /etc/shadow"
        fi
    else
        add_result "5.4.2" "Ensure permissions on /etc/shadow are configured" "Skipped" "High" "Quick" "Cannot check: stat command or /etc/shadow not available."
    fi
}

# Check 17: Ensure permissions on /etc/group are configured
check_group_permissions() {
    echo "[DEBUG] Checking /etc/group permissions" >> "$DEBUG_LOG"
    if check_command "stat" && [ -f /etc/group ]; then
        local perms owner group
        perms=$(stat -c "%a" /etc/group 2>>"$DEBUG_LOG")
        owner=$(stat -c "%U" /etc/group 2>>"$DEBUG_LOG")
        group=$(stat -c "%G" /etc/group 2>>"$DEBUG_LOG")
        if [ "$perms" = "644" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
            add_result "5.4.3" "Ensure permissions on /etc/group are configured" "Pass" "Medium" "Quick" "Run: chmod 644 /etc/group; chown root:root /etc/group"
        else
            add_result "5.4.3" "Ensure permissions on /etc/group are configured" "Fail" "Medium" "Quick" "Run: chmod 644 /etc/group; chown root:root /etc/group"
        fi
    else
        add_result "5.4.3" "Ensure permissions on /etc/group are configured" "Skipped" "Medium" "Quick" "Cannot check: stat command or /etc/group not available."
    fi
}

# Check 18: Ensure permissions on /etc/gshadow are configured
check_gshadow_permissions() {
    echo "[DEBUG] Checking /etc/gshadow permissions" >> "$DEBUG_LOG"
    if check_command "stat" && [ -f /etc/gshadow ]; then
        local perms owner group
        perms=$(stat -c "%a" /etc/gshadow 2>>"$DEBUG_LOG")
        owner=$(stat -c "%U" /etc/gshadow 2>>"$DEBUG_LOG")
        group=$(stat -c "%G" /etc/gshadow 2>>"$DEBUG_LOG")
        if [ "$perms" = "640" ] && [ "$owner" = "root" ] && [ "$group" = "shadow" ]; then
            add_result "5.4.4" "Ensure permissions on /etc/gshadow are configured" "Pass" "High" "Quick" "Run: chmod 640 /etc/gshadow; chown root:shadow /etc/gshadow"
        else
            add_result "5.4.4" "Ensure permissions on /etc/gshadow are configured" "Fail" "High" "Quick" "Run: chmod 640 /etc/gshadow; chown root:shadow /etc/gshadow"
        fi
    else
        add_result "5.4.4" "Ensure permissions on /etc/gshadow are configured" "Skipped" "High" "Quick" "Cannot check: stat command or /etc/gshadow not available."
    fi
}

# Check 19: Ensure cron daemon is enabled
check_cron_enabled() {
    echo "[DEBUG] Checking cron service" >> "$DEBUG_LOG"
    if check_command "systemctl"; then
        if systemctl is-enabled cron >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "3.5.1" "Ensure cron daemon is enabled" "Pass" "Medium" "Quick" "Run: systemctl enable cron; systemctl start cron"
        else
            add_result "3.5.1" "Ensure cron daemon is enabled" "Fail" "Medium" "Quick" "Run: systemctl enable cron; systemctl start cron"
        fi
    else
        add_result "3.5.1" "Ensure cron daemon is enabled" "Skipped" "Medium" "Quick" "Cannot check: systemctl command not available."
    fi
}

# Check 20: Ensure permissions on /etc/crontab are configured
check_crontab_permissions() {
    echo "[DEBUG] Checking /etc/crontab permissions" >> "$DEBUG_LOG"
    if check_command "stat" && [ -f /etc/crontab ]; then
        local perms owner group
        perms=$(stat -c "%a" /etc/crontab 2>>"$DEBUG_LOG")
        owner=$(stat -c "%U" /etc/crontab 2>>"$DEBUG_LOG")
        group=$(stat -c "%G" /etc/crontab 2>>"$DEBUG_LOG")
        if [ "$perms" = "600" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
            add_result "5.1.1" "Ensure permissions on /etc/crontab are configured" "Pass" "Medium" "Quick" "Run: chmod 600 /etc/crontab; chown root:root /etc/crontab"
        else
            add_result "5.1.1" "Ensure permissions on /etc/crontab are configured" "Fail" "Medium" "Quick" "Run: chmod 600 /etc/crontab; chown root:root /etc/crontab"
        fi
    else
        add_result "5.1.1" "Ensure permissions on /etc/crontab are configured" "Skipped" "Medium" "Quick" "Cannot check: stat command or /etc/crontab not available."
    fi
}

# Check 21: Ensure permissions on /etc/cron.d are configured
check_cron_d_permissions() {
    echo "[DEBUG] Checking /etc/cron.d permissions" >> "$DEBUG_LOG"
    if check_command "stat" && [ -d /etc/cron.d ]; then
        local perms owner group
        perms=$(stat -c "%a" /etc/cron.d 2>>"$DEBUG_LOG")
        owner=$(stat -c "%U" /etc/cron.d 2>>"$DEBUG_LOG")
        group=$(stat -c "%G" /etc/cron.d 2>>"$DEBUG_LOG")
        if [ "$perms" = "700" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
            add_result "5.1.8" "Ensure permissions on /etc/cron.d are configured" "Pass" "Medium" "Quick" "Run: chmod 700 /etc/cron.d; chown root:root /etc/cron.d"
        else
            add_result "5.1.8" "Ensure permissions on /etc/cron.d are configured" "Fail" "Medium" "Quick" "Run: chmod 700 /etc/cron.d; chown root:root /etc/cron.d"
        fi
    else
        add_result "5.1.8" "Ensure permissions on /etc/cron.d are configured" "Skipped" "Medium" "Quick" "Cannot check: stat command or /etc/cron.d not available."
    fi
}

# Check 22: Ensure rsyslog service is enabled
check_rsyslog_enabled() {
    echo "[DEBUG] Checking rsyslog service" >> "$DEBUG_LOG"
    if check_command "systemctl"; then
        if systemctl is-enabled rsyslog >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "4.2.1" "Ensure rsyslog service is enabled" "Pass" "Medium" "Quick" "Run: apt install rsyslog; systemctl enable rsyslog; systemctl start rsyslog"
        else
            add_result "4.2.1" "Ensure rsyslog service is enabled" "Fail" "Medium" "Quick" "Run: apt install rsyslog; systemctl enable rsyslog; systemctl start rsyslog"
        fi
    else
        add_result "4.2.1" "Ensure rsyslog service is enabled" "Skipped" "Medium" "Quick" "Cannot check: systemctl command not available."
    fi
}

# Check 23: Ensure logrotate is installed
check_logrotate_installed() {
    echo "[DEBUG] Checking logrotate installation" >> "$DEBUG_LOG"
    if check_command "dpkg"; then
        if dpkg -s logrotate >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "4.3.1" "Ensure logrotate is installed" "Pass" "Medium" "Quick" "Run: apt install logrotate"
        else
            add_result "4.3.1" "Ensure logrotate is installed" "Fail" "Medium" "Quick" "Run: apt install logrotate"
        fi
    else
        add_result "4.3.1" "Ensure logrotate is installed" "Skipped" "Medium" "Quick" "Cannot check: dpkg command not available."
    fi
}

# Check 24: Ensure telnet server is not installed
check_telnet_server() {
    echo "[DEBUG] Checking telnet server" >> "$DEBUG_LOG"
    if check_command "dpkg"; then
        if ! dpkg -s telnetd >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "2.2.1" "Ensure telnet server is not installed" "Pass" "High" "Quick" "Run: apt remove telnetd"
        else
            add_result "2.2.1" "Ensure telnet server is not installed" "Fail" "High" "Quick" "Run: apt remove telnetd"
        fi
    else
        add_result "2.2.1" "Ensure telnet server is not installed" "Skipped" "High" "Quick" "Cannot check: dpkg command not available."
    fi
}

# Check 25: Ensure FTP server is not installed
check_ftp_server() {
    echo "[DEBUG] Checking FTP server" >> "$DEBUG_LOG"
    if check_command "dpkg"; then
        if ! dpkg -s vsftpd >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "2.2.2" "Ensure FTP server is not installed" "Pass" "High" "Quick" "Run: apt remove vsftpd"
        else
            add_result "2.2.2" "Ensure FTP server is not installed" "Fail" "High" "Quick" "Run: apt remove vsftpd"
        fi
    else
        add_result "2.2.2" "Ensure FTP server is not installed" "Skipped" "High" "Quick" "Cannot check: dpkg command not available."
    fi
}

# Check 26: Ensure NFS server is not installed
check_nfs_server() {
    echo "[DEBUG] Checking NFS server" >> "$DEBUG_LOG"
    if check_command "dpkg"; then
        if ! dpkg -s nfs-kernel-server >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "2.2.3" "Ensure NFS server is not installed" "Pass" "Medium" "Quick" "Run: apt remove nfs-kernel-server"
        else
            add_result "2.2.3" "Ensure NFS server is not installed" "Fail" "Medium" "Quick" "Run: apt remove nfs-kernel-server"
        fi
    else
        add_result "2.2.3" "Ensure NFS server is not installed" "Skipped" "Medium" "Quick" "Cannot check: dpkg command not available."
    fi
}

# Check 27: Ensure DNS server is not installed
check_dns_server() {
    echo "[DEBUG] Checking DNS server" >> "$DEBUG_LOG"
    if check_command "dpkg"; then
        if ! dpkg -s bind9 >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "2.2.4" "Ensure DNS server is not installed" "Pass" "Medium" "Quick" "Run: apt remove bind9"
        else
            add_result "2.2.4" "Ensure DNS server is not installed" "Fail" "Medium" "Quick" "Run: apt remove bind9"
        fi
    else
        add_result "2.2.4" "Ensure DNS server is not installed" "Skipped" "Medium" "Quick" "Cannot check: dpkg command not available."
    fi
}

# Check 28: Ensure mail transfer agent is configured for local-only
check_mta_local_only() {
    echo "[DEBUG] Checking MTA configuration" >> "$DEBUG_LOG"
    if check_command "systemctl" && [ -f /etc/postfix/main.cf ]; then
        if ! systemctl is-active postfix >/dev/null 2>>"$DEBUG_LOG" || grep -q "inet_interfaces = loopback-only" /etc/postfix/main.cf 2>>"$DEBUG_LOG"; then
            add_result "2.2.5" "Ensure mail transfer agent is configured for local-only" "Pass" "Medium" "Quick" "Edit /etc/postfix/main.cf and set 'inet_interfaces = loopback-only'. Restart postfix."
        else
            add_result "2.2.5" "Ensure mail transfer agent is configured for local-only" "Fail" "Medium" "Quick" "Edit /etc/postfix/main.cf and set 'inet_interfaces = loopback-only'. Restart postfix."
        fi
    else
        add_result "2.2.5" "Ensure mail transfer agent is configured for local-only" "Skipped" "Medium" "Quick" "Cannot check: systemctl command or /etc/postfix/main.cf not available."
    fi
}

# Check 29: Ensure chrony is configured
check_chrony_configured() {
    echo "[DEBUG] Checking chrony configuration" >> "$DEBUG_LOG"
    if check_command "dpkg" && check_command "systemctl"; then
        if dpkg -s chrony >/dev/null 2>>"$DEBUG_LOG" && systemctl is-enabled chrony >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "2.2.6" "Ensure chrony is configured" "Pass" "Medium" "Quick" "Run: apt install chrony; systemctl enable chrony; systemctl start chrony"
        else
            add_result "2.2.6" "Ensure chrony is configured" "Fail" "Medium" "Quick" "Run: apt install chrony; systemctl enable chrony; systemctl start chrony"
        fi
    else
        add_result "2.2.6" "Ensure chrony is configured" "Skipped" "Medium" "Quick" "Cannot check: dpkg or systemctl command not available."
    fi
}

# Check 30: Ensure X Window System is not installed
check_x_window_system() {
    echo "[DEBUG] Checking X Window System" >> "$DEBUG_LOG"
    if check_command "dpkg"; then
        if ! dpkg -s xserver-xorg >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "2.2.7" "Ensure X Window System is not installed" "Pass" "Medium" "Quick" "Run: apt remove xserver-xorg"
        else
            add_result "2.2.7" "Ensure X Window System is not installed" "Fail" "Medium" "Quick" "Run: apt remove xserver-xorg"
        fi
    else
        add_result "2.2.7" "Ensure X Window System is not installed" "Skipped" "Medium" "Quick" "Cannot check: dpkg command not available."
    fi
}

# Check 31: Ensure Avahi server is not installed
check_avahi_server() {
    echo "[DEBUG] Checking Avahi server" >> "$DEBUG_LOG"
    if check_command "dpkg"; then
        if ! dpkg -s avahi-daemon >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "2.2.8" "Ensure Avahi server is not installed" "Pass" "Medium" "Quick" "Run: apt remove avahi-daemon"
        else
            add_result "2.2.8" "Ensure Avahi server is not installed" "Fail" "Medium" "Quick" "Run: apt remove avahi-daemon"
        fi
    else
        add_result "2.2.8" "Ensure Avahi server is not installed" "Skipped" "Medium" "Quick" "Cannot check: dpkg command not available."
    fi
}

# Check 32: Ensure CUPS is not installed
check_cups() {
    echo "[DEBUG] Checking CUPS" >> "$DEBUG_LOG"
    if check_command "dpkg"; then
        if ! dpkg -s cups >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "2.2.9" "Ensure CUPS is not installed" "Pass" "Medium" "Quick" "Run: apt remove cups"
        else
            add_result "2.2.9" "Ensure CUPS is not installed" "Fail" "Medium" "Quick" "Run: apt remove cups"
        fi
    else
        add_result "2.2.9" "Ensure CUPS is not installed" "Skipped" "Medium" "Quick" "Cannot check: dpkg command not available."
    fi
}

# Check 33: Ensure DHCP server is not installed
check_dhcp_server() {
    echo "[DEBUG] Checking DHCP server" >> "$DEBUG_LOG"
    if check_command "dpkg"; then
        if ! dpkg -s isc-dhcp-server >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "2.2.10" "Ensure DHCP server is not installed" "Pass" "Medium" "Quick" "Run: apt remove isc-dhcp-server"
        else
            add_result "2.2.10" "Ensure DHCP server is not installed" "Fail" "Medium" "Quick" "Run: apt remove isc-dhcp-server"
        fi
    else
        add_result "2.2.10" "Ensure DHCP server is not installed" "Skipped" "Medium" "Quick" "Cannot check: dpkg command not available."
    fi
}

# Check 34: Ensure LDAP server is not installed
check_ldap_server() {
    echo "[DEBUG] Checking LDAP server" >> "$DEBUG_LOG"
    if check_command "dpkg"; then
        if ! dpkg -s slapd >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "2.2.11" "Ensure LDAP server is not installed" "Pass" "Medium" "Quick" "Run: apt remove slapd"
        else
            add_result "2.2.11" "Ensure LDAP server is not installed" "Fail" "Medium" "Quick" "Run: apt remove slapd"
        fi
    else
        add_result "2.2.11" "Ensure LDAP server is not installed" "Skipped" "Medium" "Quick" "Cannot check: dpkg command not available."
    fi
}

# Check 35: Ensure SNMP server is not installed
check_snmp_server() {
    echo "[DEBUG] Checking SNMP server" >> "$DEBUG_LOG"
    if check_command "dpkg"; then
        if ! dpkg -s snmpd >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "2.2.12" "Ensure SNMP server is not installed" "Pass" "Medium" "Quick" "Run: apt remove snmpd"
        else
            add_result "2.2.12" "Ensure SNMP server is not installed" "Fail" "Medium" "Quick" "Run: apt remove snmpd"
        fi
    else
        add_result "2.2.12" "Ensure SNMP server is not installed" "Skipped" "Medium" "Quick" "Cannot check: dpkg command not available."
    fi
}

# Check 36: Ensure Samba is not installed
check_samba() {
    echo "[DEBUG] Checking Samba" >> "$DEBUG_LOG"
    if check_command "dpkg"; then
        if ! dpkg -s samba >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "2.2.13" "Ensure Samba is not installed" "Pass" "Medium" "Quick" "Run: apt remove samba"
        else
            add_result "2.2.13" "Ensure Samba is not installed" "Fail" "Medium" "Quick" "Run: apt remove samba"
        fi
    else
        add_result "2.2.13" "Ensure Samba is not installed" "Skipped" "Medium" "Quick" "Cannot check: dpkg command not available."
    fi
}

# Check 37: Ensure HTTP server is not installed
check_http_server() {
    echo "[DEBUG] Checking HTTP server" >> "$DEBUG_LOG"
    if check_command "dpkg"; then
        if ! dpkg -s apache2 >/dev/null 2>>"$DEBUG_LOG" && ! dpkg -s nginx >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "2.2.14" "Ensure HTTP server is not installed" "Pass" "Medium" "Quick" "Run: apt remove apache2 nginx"
        else
            add_result "2.2.14" "Ensure HTTP server is not installed" "Fail" "Medium" "Quick" "Run: apt remove apache2 nginx"
        fi
    else
        add_result "2.2.14" "Ensure HTTP server is not installed" "Skipped" "Medium" "Quick" "Cannot check: dpkg command not available."
    fi
}

# Check 38: Ensure IMAP and POP3 server is not installed
check_imap_pop3_server() {
    echo "[DEBUG] Checking IMAP and POP3 server" >> "$DEBUG_LOG"
    if check_command "dpkg"; then
        if ! dpkg -s dovecot-imapd >/dev/null 2>>"$DEBUG_LOG" && ! dpkg -s dovecot-pop3d >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "2.2.15" "Ensure IMAP and POP3 server is not installed" "Pass" "Medium" "Quick" "Run: apt remove dovecot-imapd dovecot-pop3d"
        else
            add_result "2.2.15" "Ensure IMAP and POP3 server is not installed" "Fail" "Medium" "Quick" "Run: apt remove dovecot-imapd dovecot-pop3d"
        fi
    else
        add_result "2.2.15" "Ensure IMAP and POP3 server is not installed" "Skipped" "Medium" "Quick" "Cannot check: dpkg command not available."
    fi
}

# Check 39: Ensure NIS server is not installed
check_nis_server() {
    echo "[DEBUG] Checking NIS server" >> "$DEBUG_LOG"
    if check_command "dpkg"; then
        if ! dpkg -s nis >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "2.2.16" "Ensure NIS server is not installed" "Pass" "Medium" "Quick" "Run: apt remove nis"
        else
            add_result "2.2.16" "Ensure NIS server is not installed" "Fail" "Medium" "Quick" "Run: apt remove nis"
        fi
    else
        add_result "2.2.16" "Ensure NIS server is not installed" "Skipped" "Medium" "Quick" "Cannot check: dpkg command not available."
    fi
}

# Check 40: Ensure rsh server is not installed
check_rsh_server() {
    echo "[DEBUG] Checking rsh server" >> "$DEBUG_LOG"
    if check_command "dpkg"; then
        if ! dpkg -s rsh-server >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "2.2.17" "Ensure rsh server is not installed" "Pass" "High" "Quick" "Run: apt remove rsh-server"
        else
            add_result "2.2.17" "Ensure rsh server is not installed" "Fail" "High" "Quick" "Run: apt remove rsh-server"
        fi
    else
        add_result "2.2.17" "Ensure rsh server is not installed" "Skipped" "High" "Quick" "Cannot check: dpkg command not available."
    fi
}

# Check 41: Ensure bootloader password is set
check_bootloader_password() {
    echo "[DEBUG] Checking bootloader password" >> "$DEBUG_LOG"
    if [ -f /boot/grub/grub.cfg ]; then
        if grep -q "set superusers=" /boot/grub/grub.cfg 2>>"$DEBUG_LOG"; then
            add_result "1.5.1" "Ensure bootloader password is set" "Pass" "High" "Quick" "Set a password for GRUB: grub-mkpasswd-pbkdf2"
        else
            add_result "1.5.1" "Ensure bootloader password is set" "Fail" "High" "Quick" "Set a password for GRUB: grub-mkpasswd-pbkdf2"
        fi
    else
        add_result "1.5.1" "Ensure bootloader password is set" "Skipped" "High" "Quick" "Cannot check: /boot/grub/grub.cfg not available."
    fi
}

# Check 42: Ensure /etc/motd is configured
check_motd() {
    echo "[DEBUG] Checking /etc/motd" >> "$DEBUG_LOG"
    if [ -s /etc/motd ]; then
        add_result "5.7.1" "Ensure /etc/motd is configured" "Pass" "Low" "Quick" "Edit /etc/motd to include a legal banner."
    else
        add_result "5.7.1" "Ensure /etc/motd is configured" "Fail" "Low" "Quick" "Edit /etc/motd to include a legal banner."
    fi
}

# Check 43: Ensure GDM is configured properly
check_gdm() {
    echo "[DEBUG] Checking GDM configuration" >> "$DEBUG_LOG"
    if check_command "dpkg" && check_command "systemctl"; then
        if ! dpkg -s gdm3 >/dev/null 2>>"$DEBUG_LOG" || systemctl is-enabled gdm3 >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "5.7.2" "Ensure GDM is configured properly" "Pass" "Medium" "Quick" "Run: apt remove gdm3 or configure GDM settings."
        else
            add_result "5.7.2" "Ensure GDM is configured properly" "Fail" "Medium" "Quick" "Run: apt remove gdm3 or configure GDM settings."
        fi
    else
        add_result "5.7.2" "Ensure GDM is configured properly" "Skipped" "Medium" "Quick" "Cannot check: dpkg or systemctl command not available."
    fi
}

# Check 44: Ensure AppArmor is enabled
check_apparmor() {
    echo "[DEBUG] Checking AppArmor" >> "$DEBUG_LOG"
    if check_command "dpkg" && check_command "systemctl"; then
        if dpkg -s apparmor >/dev/null 2>>"$DEBUG_LOG" && systemctl is-enabled apparmor >/dev/null 2>>"$DEBUG_LOG"; then
            add_result "1.6.1" "Ensure AppArmor is enabled" "Pass" "High" "Quick" "Run: apt install apparmor; systemctl enable apparmor"
        else
            add_result "1.6.1" "Ensure AppArmor is enabled" "Fail" "High" "Quick" "Run: apt install apparmor; systemctl enable apparmor"
        fi
    else
        add_result "1.6.1" "Ensure AppArmor is enabled" "Skipped" "High" "Quick" "Cannot check: dpkg or systemctl command not available."
    fi
}

# Check 45: Ensure separate partition exists for /home
check_home_partition() {
    echo "[DEBUG] Checking /home partition" >> "$DEBUG_LOG"
    if check_command "mountpoint"; then
        if mountpoint -q /home 2>>"$DEBUG_LOG"; then
            add_result "1.1.4.1" "Ensure separate partition exists for /home" "Pass" "High" "Involved" "Configure /home as a separate partition in /etc/fstab."
        else
            add_result "1.1.4.1" "Ensure separate partition exists for /home" "Fail" "High" "Involved" "Configure /home as a separate partition in /etc/fstab."
        fi
    else
        add_result "1.1.4.1" "Ensure separate partition exists for /home" "Skipped" "High" "Involved" "Cannot check: mountpoint command not available."
    fi
}

# Check 46: Ensure nodev option set on /home partition
check_home_nodev() {
    echo "[DEBUG] Checking nodev on /home" >> "$DEBUG_LOG"
    if check_command "mount"; then
        if mount | grep /home | grep -q nodev 2>>"$DEBUG_LOG"; then
            add_result "1.1.4.2" "Ensure nodev option set on /home partition" "Pass" "Medium" "Quick" "Add nodev option to /home in /etc/fstab and remount."
        else
            add_result "1.1.4.2" "Ensure nodev option set on /home partition" "Fail" "Medium" "Quick" "Add nodev option to /home in /etc/fstab and remount."
        fi
    else
        add_result "1.1.4.2" "Ensure nodev option set on /home partition" "Skipped" "Medium" "Quick" "Cannot check: mount command not available."
    fi
}

# Check 47: Ensure nosuid option set on /home partition
check_home_nosuid() {
    echo "[DEBUG] Checking nosuid on /home" >> "$DEBUG_LOG"
    if check_command "mount"; then
        if mount | grep /home | grep -q nosuid 2>>"$DEBUG_LOG"; then
            add_result "1.1.4.3" "Ensure nosuid option set on /home partition" "Pass" "Medium" "Quick" "Add nosuid option to /home in /etc/fstab and remount."
        else
            add_result "1.1.4.3" "Ensure nosuid option set on /home partition" "Fail" "Medium" "Quick" "Add nosuid option to /home in /etc/fstab and remount."
        fi
    else
        add_result "1.1.4.3" "Ensure nosuid option set on /home partition" "Skipped" "Medium" "Quick" "Cannot check: mount command not available."
    fi
}

# Check 48: Ensure /var/log/audit is a separate partition
check_var_log_audit_partition() {
    echo "[DEBUG] Checking /var/log/audit partition" >> "$DEBUG_LOG"
    if check_command "mountpoint"; then
        if mountpoint -q /var/log/audit 2>>"$DEBUG_LOG"; then
            add_result "1.1.5.1" "Ensure /var/log/audit is a separate partition" "Pass" "High" "Involved" "Configure /var/log/audit as a separate partition in /etc/fstab."
        else
            add_result "1.1.5.1" "Ensure /var/log/audit is a separate partition" "Fail" "High" "Involved" "Configure /var/log/audit as a separate partition in /etc/fstab."
        fi
    else
        add_result "1.1.5.1" "Ensure /var/log/audit is a separate partition" "Skipped" "High" "Involved" "Cannot check: mountpoint command not available."
    fi
}

# Check 49: Ensure permissions on /etc/fstab are configured
check_fstab_permissions() {
    echo "[DEBUG] Checking /etc/fstab permissions" >> "$DEBUG_LOG"
    if check_command "stat" && [ -f /etc/fstab ]; then
        local perms owner group
        perms=$(stat -c "%a" /etc/fstab 2>>"$DEBUG_LOG")
        owner=$(stat -c "%U" /etc/fstab 2>>"$DEBUG_LOG")
        group=$(stat -c "%G" /etc/fstab 2>>"$DEBUG_LOG")
        if [ "$perms" = "644" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
            add_result "5.4.5" "Ensure permissions on /etc/fstab are configured" "Pass" "Medium" "Quick" "Run: chmod 644 /etc/fstab; chown root:root /etc/fstab"
        else
            add_result "5.4.5" "Ensure permissions on /etc/fstab are configured" "Fail" "Medium" "Quick" "Run: chmod 644 /etc/fstab; chown root:root /etc/fstab"
        fi
    else
        add_result "5.4.5" "Ensure permissions on /etc/fstab are configured" "Skipped" "Medium" "Quick" "Cannot check: stat command or /etc/fstab not available."
    fi
}

# Check 50: Ensure cron.hourly permissions are configured
check_cron_hourly_permissions() {
    echo "[DEBUG] Checking /etc/cron.hourly permissions" >> "$DEBUG_LOG"
    if check_command "stat" && [ -d /etc/cron.hourly ]; then
        local perms owner group
        perms=$(stat -c "%a" /etc/cron.hourly 2>>"$DEBUG_LOG")
        owner=$(stat -c "%U" /etc/cron.hourly 2>>"$DEBUG_LOG")
        group=$(stat -c "%G" /etc/cron.hourly 2>>"$DEBUG_LOG")
        if [ "$perms" = "700" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
            add_result "5.1.2" "Ensure permissions on /etc/cron.hourly are configured" "Pass" "Medium" "Quick" "Run: chmod 700 /etc/cron.hourly; chown root:root /etc/cron.hourly"
        else
            add_result "5.1.2" "Ensure permissions on /etc/cron.hourly are configured" "Fail" "Medium" "Quick" "Run: chmod 700 /etc/cron.hourly; chown root:root /etc/cron.hourly"
        fi
    else
        add_result "5.1.2" "Ensure permissions on /etc/cron.hourly are configured" "Skipped" "Medium" "Quick" "Cannot check: stat command or /etc/cron.hourly not available."
    fi
}

# Check 51: Ensure cron.daily permissions are configured
check_cron_daily_permissions() {
    echo "[DEBUG] Checking /etc/cron.daily permissions" >> "$DEBUG_LOG"
    if check_command "stat" && [ -d /etc/cron.daily ]; then
        local perms owner group
        perms=$(stat -c "%a" /etc/cron.daily 2>>"$DEBUG_LOG")
        owner=$(stat -c "%U" /etc/cron.daily 2>>"$DEBUG_LOG")
        group=$(stat -c "%G" /etc/cron.daily 2>>"$DEBUG_LOG")
        if [ "$perms" = "700" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
            add_result "5.1.3" "Ensure permissions on /etc/cron.daily are configured" "Pass" "Medium" "Quick" "Run: chmod 700 /etc/cron.daily; chown root:root /etc/cron.daily"
        else
            add_result "5.1.3" "Ensure permissions on /etc/cron.daily are configured" "Fail" "Medium" "Quick" "Run: chmod 700 /etc/cron.daily; chown root:root /etc/cron.daily"
        fi
    else
        add_result "5.1.3" "Ensure permissions on /etc/cron.daily are configured" "Skipped" "Medium" "Quick" "Cannot check: stat command or /etc/cron.daily not available."
    fi
}

# Check 52: Ensure cron.weekly permissions are configured
check_cron_weekly_permissions() {
    echo "[DEBUG] Checking /etc/cron.weekly permissions" >> "$DEBUG_LOG"
    if check_command "stat" && [ -d /etc/cron.weekly ]; then
        local perms owner group
        perms=$(stat -c "%a" /etc/cron.weekly 2>>"$DEBUG_LOG")
        owner=$(stat -c "%U" /etc/cron.weekly 2>>"$DEBUG_LOG")
        group=$(stat -c "%G" /etc/cron.weekly 2>>"$DEBUG_LOG")
        if [ "$perms" = "700" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
            add_result "5.6.4" "Ensure permissions on /etc/cron.weekly are configured" "Pass" "Medium" "Quick" "Run: chmod 700 /etc/cron.weekly; chown root:root /etc/cron.weekly"
        else
            add_result "5.6.4" "Ensure permissions on /etc/cron.weekly are configured" "Fail" "Medium" "Quick" "Run: chmod 700 /etc/cron.weekly; chown root:root /etc/cron.weekly"
        fi
    else
        add_result "5.6.4" "Ensure permissions on /etc/cron.weekly are configured" "Skipped" "Medium" "Quick" "Cannot check: stat command or /etc/cron.weekly not available."
    fi
}

# Check 53: Ensure cron.monthly permissions are configured
check_cron_monthly_permissions() {
    echo "[DEBUG] Checking /etc/cron.monthly permissions" >> "$DEBUG_LOG"
    if check_command "stat" && [ -d /etc/cron.monthly ]; then
        local perms owner group
        perms=$(stat -c "%a" /etc/cron.monthly 2>>"$DEBUG_LOG")
        owner=$(stat -c "%U" /etc/cron.monthly 2>>"$DEBUG_LOG")
        group=$(stat -c "%G" /etc/cron.monthly 2>>"$DEBUG_LOG")
        if [ "$perms" = "700" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
            add_result "5.1.5" "Ensure permissions on /etc/cron.monthly are configured" "Pass" "Medium" "Quick" "Run: chmod 700 /etc/cron.monthly; chown root:root /etc/cron.monthly"
        else
            add_result "5.1.5" "Ensure permissions on /etc/cron.monthly are configured" "Fail" "Medium" "Quick" "Run: chmod 700 /etc/cron.monthly; chown root:root /etc/cron.monthly"
        fi
    else
        add_result "5.1.5" "Ensure permissions on /etc/cron.monthly are configured" "Skipped" "Medium" "Quick" "Cannot check: stat command or /etc/cron.monthly not available."
    fi
}

# Check 54: Ensure at is restricted
check_at_restrictions() {
    echo "[DEBUG] Checking at restrictions" >> "$DEBUG_LOG"
    if [ -f /etc/at.allow ] || [ -f /etc/at.deny ]; then
        add_result "5.1.6" "Ensure at is restricted" "Pass" "Medium" "Quick" "Configure /etc/at.allow or /etc/at.deny to restrict at access."
    else
        add_result "5.1.6" "Ensure at is restricted" "Fail" "Medium" "Quick" "Configure /etc/at.allow or /etc/at.deny to restrict at access."
    fi
}

# Check 55: Ensure SSH IgnoreRhosts is enabled
check_ssh_ignorerhosts() {
    echo "[DEBUG] Checking SSH IgnoreRhosts" >> "$DEBUG_LOG"
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^IgnoreRhosts yes" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
            add_result "5.2.7" "Ensure SSH IgnoreRhosts is enabled" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'IgnoreRhosts yes'. Restart sshd."
        else
            add_result "5.2.7" "Ensure SSH IgnoreRhosts is enabled" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'IgnoreRhosts yes'. Restart sshd."
        fi
    else
        add_result "5.2.7" "Ensure SSH IgnoreRhosts is enabled" "Skipped" "Medium" "Quick" "Cannot check: /etc/ssh/sshd_config not available."
    fi
}

# Check 56: Ensure SSH HostbasedAuthentication is disabled
check_ssh_hostbasedauth() {
    echo "[DEBUG] Checking SSH HostbasedAuthentication" >> "$DEBUG_LOG"
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^HostbasedAuthentication no" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
            add_result "5.2.8" "Ensure SSH HostbasedAuthentication is disabled" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'HostbasedAuthentication no'. Restart sshd."
        else
            add_result "5.2.8" "Ensure SSH HostbasedAuthentication is disabled" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'HostbasedAuthentication no'. Restart sshd."
        fi
    else
        add_result "5.2.8" "Ensure SSH HostbasedAuthentication is disabled" "Skipped" "Medium" "Quick" "Cannot check: /etc/ssh/sshd_config not available."
    fi
}

# Check 57: Ensure SSH AllowTcpForwarding is disabled
check_ssh_tcpforwarding() {
    echo "[DEBUG] Checking SSH AllowTcpForwarding" >> "$DEBUG_LOG"
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^AllowTcpForwarding no" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
            add_result "5.2.9" "Ensure SSH AllowTcpForwarding is disabled" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'AllowTcpForwarding no'. Restart sshd."
        else
            add_result "5.2.9" "Ensure SSH AllowTcpForwarding is disabled" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'AllowTcpForwarding no'. Restart sshd."
        fi
    else
        add_result "5.2.9" "Ensure SSH AllowTcpForwarding is disabled" "Skipped" "Medium" "Quick" "Cannot check: /etc/ssh/sshd_config not available."
    fi
}

# Check 58: Ensure SSH MaxStartups is configured
check_ssh_maxstartups() {
    echo "[DEBUG] Checking SSH MaxStartups" >> "$DEBUG_LOG"
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^MaxStartups 10:30:60" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
            add_result "5.2.10" "Ensure SSH MaxStartups is configured" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'MaxStartups 10:30:60'. Restart sshd."
        else
            add_result "5.2.10" "Ensure SSH MaxStartups is configured" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'MaxStartups 10:30:60'. Restart sshd."
        fi
    else
        add_result "5.2.10" "Ensure SSH MaxStartups is configured" "Skipped" "Medium" "Quick" "Cannot check: /etc/ssh/sshd_config not available."
    fi
}

# Check 59: Ensure SSH ClientAliveInterval is configured
check_ssh_clientaliveinterval() {
    echo "[DEBUG] Checking SSH ClientAliveInterval" >> "$DEBUG_LOG"
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^ClientAliveInterval 300" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
            add_result "5.2.11" "Ensure SSH ClientAliveInterval is configured" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'ClientAliveInterval 300'. Restart sshd."
        else
            add_result "5.2.11" "Ensure SSH ClientAliveInterval is configured" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'ClientAliveInterval 300'. Restart sshd."
        fi
    else
        add_result "5.2.11" "Ensure SSH ClientAliveInterval is configured" "Skipped" "Medium" "Quick" "Cannot check: /etc/ssh/sshd_config not available."
    fi
}

# Check 60: Ensure SSH ClientAliveCountMax is configured
check_ssh_clientalivecountmax() {
    echo "[DEBUG] Checking SSH ClientAliveCountMax" >> "$DEBUG_LOG"
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^ClientAliveCountMax 3" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
            add_result "5.2.12" "Ensure SSH ClientAliveCountMax is configured" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'ClientAliveCountMax 3'. Restart sshd."
        else
            add_result "5.2.12" "Ensure SSH ClientAliveCountMax is configured" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'ClientAliveCountMax 3'. Restart sshd."
        fi
    else
        add_result "5.2.12" "Ensure SSH ClientAliveCountMax is configured" "Skipped" "Medium" "Quick" "Cannot check: /etc/ssh/sshd_config not available."
    fi
}

# Generate HTML report
generate_html_report() {
    echo "[DEBUG] Generating HTML report" >> "$DEBUG_LOG"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    cat << EOF > cis_debian_report.html
<!DOCTYPE html>
<html>
<head>
    <title>CIS Debian Benchmark Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .pass { color: green; }
        .fail { color: red; }
        .skipped { color: gray; }
        .critical { background-color: #ffcccc; }
        .high { background-color: #ff9999; }
        .medium { background-color: #ffcc99; }
        .low { background-color: #ccffcc; }
    </style>
</head>
<body>
    <h1>CIS Debian Benchmark Report</h1>
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
EOF
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to create cis_debian_report.html" | tee -a "$DEBUG_LOG"
        exit 1
    fi

    if [ -s "$TABLE_ROWS_FILE" ]; then
        cat "$TABLE_ROWS_FILE" >> cis_debian_report.html 2>>"$DEBUG_LOG"
        if [ $? -ne 0 ]; then
            echo "[ERROR] Failed to append table rows to cis_debian_report.html" | tee -a "$DEBUG_LOG"
        fi
    else
        echo "[WARNING] No rows found in $TABLE_ROWS_FILE" | tee -a "$DEBUG_LOG"
        echo "<tr><td colspan=\"6\">No results generated. Check $DEBUG_LOG for details.</td></tr>" >> cis_debian_report.html
    fi

    cat << EOF >> cis_debian_report.html
    </table>
</body>
</html>
EOF
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to append closing tags to cis_debian_report.html" | tee -a "$DEBUG_LOG"
        exit 1
    fi
    echo "HTML report generated: cis_debian_report.html" | tee -a "$DEBUG_LOG"
}

# Check if running as root (optional for debugging in non-Linux environments)
if [ "$EUID" -ne 0 ]; then
    echo "[WARNING] This script is not running as root. Some checks may fail or be skipped." | tee -a "$DEBUG_LOG"
else
    echo "[DEBUG] Running as root" >> "$DEBUG_LOG"
fi

# Run all checks
echo "[DEBUG] Running all checks" >> "$DEBUG_LOG"
check_tmp_partition
check_tmp_nodev
check_tmp_nosuid
check_tmp_noexec
check_var_partition
check_var_log_partition
check_ssh_config_permissions
check_ssh_protocol
check_ssh_loglevel
check_ssh_maxauthtries
check_ssh_permitrootlogin
check_ssh_permitemptypasswords
check_apt_repos
check_auditd_service
check_passwd_permissions
check_shadow_permissions
check_group_permissions
check_gshadow_permissions
check_cron_enabled
check_crontab_permissions
check_cron_d_permissions
check_rsyslog_enabled
check_logrotate_installed
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
check_bootloader_password
check_motd
check_gdm
check_apparmor
check_home_partition
check_home_nodev
check_home_nosuid
check_var_log_audit_partition
check_fstab_permissions
check_cron_hourly_permissions
check_cron_daily_permissions
check_cron_weekly_permissions
check_cron_monthly_permissions
check_at_restrictions
check_ssh_ignorerhosts
check_ssh_hostbasedauth
check_ssh_tcpforwarding
check_ssh_maxstartups
check_ssh_clientaliveinterval
check_ssh_clientalivecountmax

# Generate report
generate_html_report

# Clean up
echo "[DEBUG] Cleaning up temporary file" >> "$DEBUG_LOG"
rm -f "$TABLE_ROWS_FILE" 2>>"$DEBUG_LOG"
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to remove temporary file $TABLE_ROWS_FILE" | tee -a "$DEBUG_LOG"
fi
echo "[DEBUG] Script completed at $(date '+%Y-%m-%d %H:%M:%S')" >> "$DEBUG_LOG"
