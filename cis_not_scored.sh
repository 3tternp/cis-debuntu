#!/bin/bash

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Initialize variables
TABLE_ROWS_FILE=$(mktemp)
PASS_COUNT=0
FAIL_COUNT=0
DEBUG_LOG="cis_debug.log"
: > "$DEBUG_LOG" # Clear debug log

# Clean up temporary file on exit
trap 'rm -f "$TABLE_ROWS_FILE"' EXIT

# Function to log debug messages
log_debug() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$DEBUG_LOG"
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

    # Sanitize inputs to prevent quote and control character issues
    issue_name=$(echo "$issue_name" | sed 's/[[:cntrl:]]//g; s/"/\\"/g; s/`/\\`/g; s/'\''/\\'\''/g')
    remediation=$(echo "$remediation" | sed 's/[[:cntrl:]]//g; s/"/\\"/g; s/`/\\`/g; s/'\''/\\'\''/g')

    # Escape HTML special characters
    issue_name=$(echo "$issue_name" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'\''/\&apos;/g')
    remediation=$(echo "$remediation" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'\''/\&apos;/g')

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

    cat << EOF > cis_debian_not_scored_report.html 2>>"$DEBUG_LOG"
<!DOCTYPE html>
<html>
<head>
    <title>CIS Debian Linux 12 Not Scored Benchmark Report</title>
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
    <h1>CIS Debian Linux 12 Not Scored Benchmark Report</h1>
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
        <canvas id="complianceChart"></canvas>
    </div>
    <script>
        const ctx = document.getElementById('complianceChart').getContext('2d');
        const complianceChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: ['Pass', 'Fail'],
                datasets: [{
                    data: [$PASS_COUNT, $FAIL_COUNT],
                    backgroundColor: ['#36a2eb', '#ff6384'],
                    borderColor: ['#ffffff', '#ffffff'],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'top' },
                    title: { display: true, text: 'CIS Not Scored Compliance Status' }
                }
            }
        });
    </script>
</body>
</html>
EOF
    if [ $? -eq 0 ]; then
        echo "Report generated: cis_debian_not_scored_report.html"
        log_debug "Report generated successfully"
    else
        log_debug "Failed to generate HTML report"
        echo "Error: Failed to generate HTML report. Check $DEBUG_LOG for details." >&2
        exit 1
    fi
}

# Not Scored Checks (40 from CIS Debian Linux 12 Benchmark v1.0.1)
check_motd() {
    log_debug "Running check_motd"
    if [ -s /etc/motd ] 2>>"$DEBUG_LOG"; then
        add_result "1.7.1" "Ensure message of the day is configured properly" "Pass" "Low" "Planned" "Edit /etc/motd to include a legal banner."
    else
        add_result "1.7.1" "Ensure message of the day is configured properly" "Fail" "Low" "Planned" "Edit /etc/motd to include a legal banner."
    fi
}

check_issue() {
    log_debug "Running check_issue"
    if [ -s /etc/issue ] 2>>"$DEBUG_LOG"; then
        add_result "1.7.2" "Ensure local login warning banner is configured properly" "Pass" "Low" "Planned" "Edit /etc/issue to include a legal banner."
    else
        add_result "1.7.2" "Ensure local login warning banner is configured properly" "Fail" "Low" "Planned" "Edit /etc/issue to include a legal banner."
    fi
}

check_issue_net() {
    log_debug "Running check_issue_net"
    if [ -s /etc/issue.net ] 2>>"$DEBUG_LOG"; then
        add_result "1.7.3" "Ensure remote login warning banner is configured properly" "Pass" "Low" "Planned" "Edit /etc/issue.net to include a legal banner."
    else
        add_result "1.7.3" "Ensure remote login warning banner is configured properly" "Fail" "Low" "Planned" "Edit /etc/issue.net to include a legal banner."
    fi
}

check_gdm_banner() {
    log_debug "Running check_gdm_banner"
    if ! dpkg -s gdm3 >/dev/null 2>>"$DEBUG_LOG" || grep -q "banner-message-enable=true" /etc/gdm3/greeter.dconf-defaults 2>>"$DEBUG_LOG"; then
        add_result "1.7.4" "Ensure GDM login banner is configured" "Pass" "Low" "Planned" "Edit /etc/gdm3/greeter.dconf-defaults to enable banner-message."
    else
        add_result "1.7.4" "Ensure GDM login banner is configured" "Fail" "Low" "Planned" "Edit /etc/gdm3/greeter.dconf-defaults to enable banner-message."
    fi
}

check_apt_gpg() {
    log_debug "Running check_apt_gpg"
    if apt-key list >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "3.4.1" "Ensure GPG keys are configured" "Pass" "Medium" "Quick" "Run: apt-key update"
    else
        add_result "3.4.1" "Ensure GPG keys are configured" "Fail" "Medium" "Quick" "Run: apt-key update"
    fi
}

check_apt_repos() {
    log_debug "Running check_apt_repos"
    if apt update >/dev/null 2>>"$DEBUG_LOG"; then
        add_result "3.4.2" "Ensure package manager repositories are configured" "Pass" "Low" "Planned" "Configure valid repositories in /etc/apt/sources.list."
    else
        add_result "3.4.2" "Ensure package manager repositories are configured" "Fail" "Low" "Planned" "Configure valid repositories in /etc/apt/sources.list."
    fi
}

check_unattended_upgrades() {
    log_debug "Running check_unattended_upgrades"
    if dpkg -s unattended-upgrades >/dev/null 2>>"$DEBUG_LOG" && [ -f /etc/apt/apt.conf.d/50unattended-upgrades ] 2>>"$DEBUG_LOG"; then
        add_result "3.4.3" "Ensure package manager updates are configured" "Pass" "Medium" "Quick" "Run: apt install unattended-upgrades"
    else
        add_result "3.4.3" "Ensure package manager updates are configured" "Fail" "Medium" "Quick" "Run: apt install unattended-upgrades"
    fi
}

check_auditd_config() {
    log_debug "Running check_auditd_config"
    if [ -f /etc/audit/auditd.conf ] && grep -q "space_left_action = email" /etc/audit/auditd.conf 2>>"$DEBUG_LOG"; then
        add_result "4.1.2.1" "Ensure auditd configuration is appropriate" "Pass" "Medium" "Planned" "Configure /etc/audit/auditd.conf with appropriate settings."
    else
        add_result "4.1.2.1" "Ensure auditd configuration is appropriate" "Fail" "Medium" "Planned" "Configure /etc/audit/auditd.conf with appropriate settings."
    fi
}

check_rsyslog_remote() {
    log_debug "Running check_rsyslog_remote"
    if grep -q "*.* @@" /etc/rsyslog.conf 2>>"$DEBUG_LOG"; then
        add_result "4.2.3" "Ensure rsyslog is configured to send logs to a remote server" "Pass" "Medium" "Planned" "Configure rsyslog to send logs to a remote server in /etc/rsyslog.conf."
    else
        add_result "4.2.3" "Ensure rsyslog is configured to send logs to a remote server" "Fail" "Medium" "Planned" "Configure rsyslog to send logs to a remote server in /etc/rsyslog.conf."
    fi
}

check_rsyslog_permissions() {
    log_debug "Running check_rsyslog_permissions"
    if grep -q "^\\$FileCreateMode 0640" /etc/rsyslog.conf 2>>"$DEBUG_LOG"; then
        add_result "4.2.4" "Ensure rsyslog default file permissions configured" "Pass" "Medium" "Quick" "Edit /etc/rsyslog.conf and set '\$FileCreateMode 0640'."
    else
        add_result "4.2.4" "Ensure rsyslog default file permissions configured" "Fail" "Medium" "Quick" "Edit /etc/rsyslog.conf and set '\$FileCreateMode 0640'."
    fi
}

check_logrotate_config() {
    log_debug "Running check_logrotate_config"
    if [ -f /etc/logrotate.conf ] && grep -q "weekly" /etc/logrotate.conf 2>>"$DEBUG_LOG"; then
        add_result "4.3.1" "Ensure logrotate is configured" "Pass" "Low" "Planned" "Configure /etc/logrotate.conf with appropriate settings."
    else
        add_result "4.3.1" "Ensure logrotate is configured" "Fail" "Low" "Planned" "Configure /etc/logrotate.conf with appropriate settings."
    fi
}

check_ssh_banner() {
    log_debug "Running check_ssh_banner"
    if grep -q "^Banner" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
        add_result "5.2.16" "Ensure SSH warning banner is configured" "Pass" "Low" "Planned" "Edit /etc/ssh/sshd_config and set 'Banner /etc/issue.net'. Restart sshd."
    else
        add_result "5.2.16" "Ensure SSH warning banner is configured" "Fail" "Low" "Planned" "Edit /etc/ssh/sshd_config and set 'Banner /etc/issue.net'. Restart sshd."
    fi
}

check_ssh_ciphers() {
    log_debug "Running check_ssh_ciphers"
    if grep -q "^Ciphers aes256-ctr,aes192-ctr,aes128-ctr" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
        add_result "5.2.17" "Ensure SSH ciphers are configured" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'Ciphers aes256-ctr,aes192-ctr,aes128-ctr'. Restart sshd."
    else
        add_result "5.2.17" "Ensure SSH ciphers are configured" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'Ciphers aes256-ctr,aes192-ctr,aes128-ctr'. Restart sshd."
    fi
}

check_ssh_macs() {
    log_debug "Running check_ssh_macs"
    if grep -q "^MACs hmac-sha2-512,hmac-sha2-256" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
        add_result "5.2.18" "Ensure SSH MACs are configured" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'MACs hmac-sha2-512,hmac-sha2-256'. Restart sshd."
    else
        add_result "5.2.18" "Ensure SSH MACs are configured" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'MACs hmac-sha2-512,hmac-sha2-256'. Restart sshd."
    fi
}

check_ssh_kex() {
    log_debug "Running check_ssh_kex"
    if grep -q "^KexAlgorithms curve25519-sha256" /etc/ssh/sshd_config 2>>"$DEBUG_LOG"; then
        add_result "5.2.19" "Ensure SSH KexAlgorithms are configured" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'KexAlgorithms curve25519-sha256'. Restart sshd."
    else
        add_result "5.2.19" "Ensure SSH KexAlgorithms are configured" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'KexAlgorithms curve25519-sha256'. Restart sshd."
    fi
}

check_password_policy() {
    log_debug "Running check_password_policy"
    if [ -f /etc/security/pwquality.conf ] && grep -q "enforce_for_root" /etc/security/pwquality.conf 2>>"$DEBUG_LOG"; then
        add_result "5.3.1.1" "Ensure password creation requirements are enforced for root" "Pass" "Medium" "Planned" "Configure /etc/security/pwquality.conf with 'enforce_for_root'."
    else
        add_result "5.3.1.1" "Ensure password creation requirements are enforced for root" "Fail" "Medium" "Planned" "Configure /etc/security/pwquality.conf with 'enforce_for_root'."
    fi
}

check_su_restriction() {
    log_debug "Running check_su_restriction"
    if [ -f /etc/pam.d/su ] && grep -q "pam_wheel.so" /etc/pam.d/su 2>>"$DEBUG_LOG"; then
        add_result "5.6" "Ensure access to the su command is restricted" "Pass" "High" "Quick" "Add 'auth required pam_wheel.so' to /etc/pam.d/su."
    else
        add_result "5.6" "Ensure access to the su command is restricted" "Fail" "High" "Quick" "Add 'auth required pam_wheel.so' to /etc/pam.d/su."
    fi
}

check_sysctl_ipv6() {
    log_debug "Running check_sysctl_ipv6"
    if sysctl net.ipv6.conf.all.disable_ipv6 | grep -q "1" 2>>"$DEBUG_LOG"; then
        add_result "3.1.1" "Ensure IPv6 is disabled if not needed" "Pass" "Low" "Quick" "Add 'net.ipv6.conf.all.disable_ipv6 = 1' to /etc/sysctl.conf."
    else
        add_result "3.1.1" "Ensure IPv6 is disabled if not needed" "Fail" "Low" "Quick" "Add 'net.ipv6.conf.all.disable_ipv6 = 1' to /etc/sysctl.conf."
    fi
}

check_sysctl_packet_redirect() {
    log_debug "Running check_sysctl_packet_redirect"
    if sysctl net.ipv4.conf.all.send_redirects | grep -q "0" 2>>"$DEBUG_LOG"; then
        add_result "3.1.2" "Ensure packet redirect sending is disabled" "Pass" "Medium" "Quick" "Add 'net.ipv4.conf.all.send_redirects = 0' to /etc/sysctl.conf."
    else
        add_result "3.1.2" "Ensure packet redirect sending is disabled" "Fail" "Medium" "Quick" "Add 'net.ipv4.conf.all.send_redirects = 0' to /etc/sysctl.conf."
    fi
}

check_sysctl_ip_forward() {
    log_debug "Running check_sysctl_ip_forward"
    if sysctl net.ipv4.ip_forward | grep -q "0" 2>>"$DEBUG_LOG"; then
        add_result "3.1.3" "Ensure IP forwarding is disabled" "Pass" "Medium" "Quick" "Add 'net.ipv4.ip_forward = 0' to /etc/sysctl.conf."
    else
        add_result "3.1.3" "Ensure IP forwarding is disabled" "Fail" "Medium" "Quick" "Add 'net.ipv4.ip_forward = 0' to /etc/sysctl.conf."
    fi
}

check_sysctl_source_route() {
    log_debug "Running check_sysctl_source_route"
    if sysctl net.ipv4.conf.all.accept_source_route | grep -q "0" 2>>"$DEBUG_LOG"; then
        add_result "3.1.4" "Ensure source routed packets are not accepted" "Pass" "Medium" "Quick" "Add 'net.ipv4.conf.all.accept_source_route = 0' to /etc/sysctl.conf."
    else
        add_result "3.1.4" "Ensure source routed packets are not accepted" "Fail" "Medium" "Quick" "Add 'net.ipv4.conf.all.accept_source_route = 0' to /etc/sysctl.conf."
    fi
}

check_sysctl_icmp_redirect() {
    log_debug "Running check_sysctl_icmp_redirect"
    if sysctl net.ipv4.conf.all.accept_redirects | grep -q "0" 2>>"$DEBUG_LOG"; then
        add_result "3.1.5" "Ensure ICMP redirects are not accepted" "Pass" "Medium" "Quick" "Add 'net.ipv4.conf.all.accept_redirects = 0' to /etc/sysctl.conf."
    else
        add_result "3.1.5" "Ensure ICMP redirects are not accepted" "Fail" "Medium" "Quick" "Add 'net.ipv4.conf.all.accept_redirects = 0' to /etc/sysctl.conf."
    fi
}

check_sysctl_secure_redirect() {
    log_debug "Running check_sysctl_secure_redirect"
    if sysctl net.ipv4.conf.all.secure_redirects | grep -q "0" 2>>"$DEBUG_LOG"; then
        add_result "3.1.6" "Ensure secure ICMP redirects are not accepted" "Pass" "Medium" "Quick" "Add 'net.ipv4.conf.all.secure_redirects = 0' to /etc/sysctl.conf."
    else
        add_result "3.1.6" "Ensure secure ICMP redirects are not accepted" "Fail" "Medium" "Quick" "Add 'net.ipv4.conf.all.secure_redirects = 0' to /etc/sysctl.conf."
    fi
}

check_sysctl_log_martians() {
    log_debug "Running check_sysctl_log_martians"
    if sysctl net.ipv4.conf.all.log_martians | grep -q "1" 2>>"$DEBUG_LOG"; then
        add_result "3.1.7" "Ensure suspicious packets are logged" "Pass" "Medium" "Quick" "Add 'net.ipv4.conf.all.log_martians = 1' to /etc/sysctl.conf."
    else
        add_result "3.1.7" "Ensure suspicious packets are logged" "Fail" "Medium" "Quick" "Add 'net.ipv4.conf.all.log_martians = 1' to /etc/sysctl.conf."
    fi
}

check_sysctl_broadcast_icmp() {
    log_debug "Running check_sysctl_broadcast_icmp"
    if sysctl net.ipv4.icmp_echo_ignore_broadcasts | grep -q "1" 2>>"$DEBUG_LOG"; then
        add_result "3.1.8" "Ensure broadcast ICMP requests are ignored" "Pass" "Medium" "Quick" "Add 'net.ipv4.icmp_echo_ignore_broadcasts = 1' to /etc/sysctl.conf."
    else
        add_result "3.1.8" "Ensure broadcast ICMP requests are ignored" "Fail" "Medium" "Quick" "Add 'net.ipv4.icmp_echo_ignore_broadcasts = 1' to /etc/sysctl.conf."
    fi
}

check_sysctl_bogus_icmp() {
    log_debug "Running check_sysctl_bogus_icmp"
    if sysctl net.ipv4.icmp_ignore_bogus_error_responses | grep -q "1" 2>>"$DEBUG_LOG"; then
        add_result "3.1.9" "Ensure bogus ICMP responses are ignored" "Pass" "Medium" "Quick" "Add 'net.ipv4.icmp_ignore_bogus_error_responses = 1' to /etc/sysctl.conf."
    else
        add_result "3.1.9" "Ensure bogus ICMP responses are ignored" "Fail" "Medium" "Quick" "Add 'net.ipv4.icmp_ignore_bogus_error_responses = 1' to /etc/sysctl.conf."
    fi
}

check_sysctl_tcp_syncookies() {
    log_debug "Running check_sysctl_tcp_syncookies"
    if sysctl net.ipv4.tcp_syncookies | grep -q "1" 2>>"$DEBUG_LOG"; then
        add_result "3.1.10" "Ensure TCP SYN Cookies is enabled" "Pass" "Medium" "Quick" "Add 'net.ipv4.tcp_syncookies = 1' to /etc/sysctl.conf."
    else
        add_result "3.1.10" "Ensure TCP SYN Cookies is enabled" "Fail" "Medium" "Quick" "Add 'net.ipv4.tcp_syncookies = 1' to /etc/sysctl.conf."
    fi
}

check_audit_backlog() {
    log_debug "Running check_audit_backlog"
    if [ -f /etc/audit/auditd.conf ] && grep -q "max_log_file_action = keep_logs" /etc/audit/auditd.conf 2>>"$DEBUG_LOG"; then
        add_result "4.1.2.2" "Ensure audit log storage size is configured" "Pass" "Medium" "Planned" "Configure /etc/audit/auditd.conf with 'max_log_file_action = keep_logs'."
    else
        add_result "4.1.2.2" "Ensure audit log storage size is configured" "Fail" "Medium" "Planned" "Configure /etc/audit/auditd.conf with 'max_log_file_action = keep_logs'."
    fi
}

check_audit_processes() {
    log_debug "Running check_audit_processes"
    if [ -f /etc/audit/audit.rules ] && grep -q "exit,always arch=b64" /etc/audit/audit.rules 2>>"$DEBUG_LOG"; then
        add_result "4.1.3" "Ensure auditing for processes that start prior to auditd is enabled" "Pass" "Medium" "Planned" "Add audit rules to /etc/audit/audit.rules."
    else
        add_result "4.1.3" "Ensure auditing for processes that start prior to auditd is enabled" "Fail" "Medium" "Planned" "Add audit rules to /etc/audit/audit.rules."
    fi
}

check_audit_events() {
    log_debug "Running check_audit_events"
    if [ -f /etc/audit/audit.rules ] && grep -q "-a always,exit -F arch=b64 -S adjtimex" /etc/audit/audit.rules 2>>"$DEBUG_LOG"; then
        add_result "4.1.4" "Ensure events that modify date and time information are collected" "Pass" "Medium" "Planned" "Add time modification audit rules to /etc/audit/audit.rules."
    else
        add_result "4.1.4" "Ensure events that modify date and time information are collected" "Fail" "Medium" "Planned" "Add time modification audit rules to /etc/audit/audit.rules."
    fi
}

check_audit_user_group() {
    log_debug "Running check_audit_user_group"
    if [ -f /etc/audit/audit.rules ] && grep -q "-w /etc/passwd -p wa" /etc/audit/audit.rules 2>>"$DEBUG_LOG"; then
        add_result "4.1.5" "Ensure events that modify user/group information are collected" "Pass" "Medium" "Planned" "Add user/group audit rules to /etc/audit/audit.rules."
    else
        add_result "4.1.5" "Ensure events that modify user/group information are collected" "Fail" "Medium" "Planned" "Add user/group audit rules to /etc/audit/audit.rules."
    fi
}

check_audit_network() {
    log_debug "Running check_audit_network"
    if [ -f /etc/audit/audit.rules ] && grep -q "-a always,exit -F arch=b64 -S sethostname" /etc/audit/audit.rules 2>>"$DEBUG_LOG"; then
        add_result "4.1.6" "Ensure events that modify network environment are collected" "Pass" "Medium" "Planned" "Add network audit rules to /etc/audit/audit.rules."
    else
        add_result "4.1.6" "Ensure events that modify network environment are collected" "Fail" "Medium" "Planned" "Add network audit rules to /etc/audit/audit.rules."
    fi
}

check_audit_logins() {
    log_debug "Running check_audit_logins"
    if [ -f /etc/audit/audit.rules ] && grep -q "-w /var/log/lastlog -p wa" /etc/audit/audit.rules 2>>"$DEBUG_LOG"; then
        add_result "4.1.7" "Ensure login and logout events are collected" "Pass" "Medium" "Planned" "Add login audit rules to /etc/audit/audit.rules."
    else
        add_result "4.1.7" "Ensure login and logout events are collected" "Fail" "Medium" "Planned" "Add login audit rules to /etc/audit/audit.rules."
    fi
}

check_audit_permissions() {
    log_debug "Running check_audit_permissions"
    if [ -f /etc/audit/audit.rules ] && grep -q "-a always,exit -F arch=b64 -S chmod" /etc/audit/audit.rules 2>>"$DEBUG_LOG"; then
        add_result "4.1.8" "Ensure changes to file permissions are collected" "Pass" "Medium" "Planned" "Add permissions audit rules to /etc/audit/audit.rules."
    else
        add_result "4.1.8" "Ensure changes to file permissions are collected" "Fail" "Medium" "Planned" "Add permissions audit rules to /etc/audit/audit.rules."
    fi
}

check_audit_privileged() {
    log_debug "Running check_audit_privileged"
    if [ -f /etc/audit/audit.rules ] && grep -q "-a always,exit -F arch=b64 -S execve" /etc/audit/audit.rules 2>>"$DEBUG_LOG"; then
        add_result "4.1.9" "Ensure privileged commands are collected" "Pass" "Medium" "Planned" "Add privileged command audit rules to /etc/audit/audit.rules."
    else
        add_result "4.1.9" "Ensure privileged commands are collected" "Fail" "Medium" "Planned" "Add privileged command audit rules to /etc/audit/audit.rules."
    fi
}

check_audit_mounts() {
    log_debug "Running check_audit_mounts"
    if [ -f /etc/audit/audit.rules ] && grep -q "-a always,exit -F arch=b64 -S mount" /etc/audit/audit.rules 2>>"$DEBUG_LOG"; then
        add_result "4.1.10" "Ensure filesystem mounts are collected" "Pass" "Medium" "Planned" "Add mount audit rules to /etc/audit/audit.rules."
    else
        add_result "4.1.10" "Ensure filesystem mounts are collected" "Fail" "Medium" "Planned" "Add mount audit rules to /etc/audit/audit.rules."
    fi
}

# Execute all checks
run_checks() {
    echo "Running CIS Debian Linux 12 Not Scored Checks..."
    log_debug "Starting checks"
    check_motd
    check_issue
    check_issue_net
    check_gdm_banner
    check_apt_gpg
    check_apt_repos
    check_unattended_upgrades
    check_auditd_config
    check_rsyslog_remote
    check_rsyslog_permissions
    check_logrotate_config
    check_ssh_banner
    check_ssh_ciphers
    check_ssh_macs
    check_ssh_kex
    check_password_policy
    check_su_restriction
    check_sysctl_ipv6
    check_sysctl_packet_redirect
    check_sysctl_ip_forward
    check_sysctl_source_route
    check_sysctl_icmp_redirect
    check_sysctl_secure_redirect
    check_sysctl_log_martians
    check_sysctl_broadcast_icmp
    check_sysctl_bogus_icmp
    check_sysctl_tcp_syncookies
    check_audit_backlog
    check_audit_processes
    check_audit_events
    check_audit_user_group
    check_audit_network
    check_audit_logins
    check_audit_permissions
    check_audit_privileged
    check_audit_mounts
    log_debug "Checks completed"
}

# Main execution
main() {
    run_checks
    generate_html_report
}

main
