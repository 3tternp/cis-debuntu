#!/bin/bash

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Initialize temporary file for HTML table rows
TABLE_ROWS_FILE=$(mktemp)

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
    issue_name=$(echo "$issue_name" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'\''/\&apos;/g')
    remediation=$(echo "$remediation" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'\''/\&apos;/g')
    echo "<tr class=\"$risk_class\"><td>$finding_id</td><td>$issue_name</td><td class=\"$status_class\">$status</td><td>$risk_rating</td><td>$fix_type</td><td>$remediation</td></tr>" >> "$TABLE_ROWS_FILE"
}

# Check 1: Ensure /tmp is configured as a separate partition
check_tmp_partition() {
    if mountpoint -q /tmp; then
        add_result "1.1.1.1" "Ensure /tmp is configured as a separate partition" "Pass" "High" "Involved" "Configure /tmp as a separate partition in /etc/fstab with options like nosuid, noexec, nodev."
    else
        add_result "1.1.1.1" "Ensure /tmp is configured as a separate partition" "Fail" "High" "Involved" "Configure /tmp as a separate partition in /etc/fstab with options like nosuid, noexec, nodev."
    fi
}

# Check 2: Ensure permissions on /etc/ssh/sshd_config are configured
check_ssh_config_permissions() {
    local perms
    local owner
    local group
    perms=$(stat -c "%a" /etc/ssh/sshd_config 2>/dev/null)
    owner=$(stat -c "%U" /etc/ssh/sshd_config 2>/dev/null)
    group=$(stat -c "%G" /etc/ssh/sshd_config 2>/dev/null)
    if [ "$perms" = "600" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        add_result "5.2.1" "Ensure permissions on /etc/ssh/sshd_config are configured" "Pass" "Medium" "Quick" "Run: chmod 600 /etc/ssh/sshd_config; chown root:root /etc/ssh/sshd_config"
    else
        add_result "5.2.1" "Ensure permissions on /etc/ssh/sshd_config are configured" "Fail" "Medium" "Quick" "Run: chmod 600 /etc/ssh/sshd_config; chown root:root /etc/ssh/sshd_config"
    fi
}

# Check 3: Ensure SSH Protocol is set to 2
check_ssh_protocol() {
    if grep -q "^Protocol 2" /etc/ssh/sshd_config 2>/dev/null; then
        add_result "5.2.2" "Ensure SSH Protocol is set to 2" "Pass" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'Protocol 2'. Restart sshd: systemctl restart sshd"
    else
        add_result "5.2.2" "Ensure SSH Protocol is set to 2" "Fail" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'Protocol 2'. Restart sshd: systemctl restart sshd"
    fi
}

# Check 4: Ensure package manager repositories are configured
check_apt_repos() {
    if apt update >/dev/null 2>&1; then
        add_result "3.1.2" "Ensure package manager repositories are configured" "Pass" "Low" "Planned" "Configure valid repositories in /etc/apt/sources.list and ensure they are accessible."
    else
        add_result "3.1.2" "Ensure package manager repositories are configured" "Fail" "Low" "Planned" "Configure valid repositories in /etc/apt/sources.list and ensure they are accessible."
    fi
}

# Check 5: Ensure auditd service is enabled
check_auditd_service() {
    if systemctl is-enabled auditd >/dev/null 2>&1; then
        add_result "4.1.1" "Ensure auditd service is enabled" "Pass" "Critical" "Quick" "Run: apt install auditd; systemctl enable auditd; systemctl start auditd"
    else
        add_result "4.1.1" "Ensure auditd service is enabled" "Fail" "Critical" "Quick" "Run: apt install auditd; systemctl enable auditd; systemctl start auditd"
    fi
}

# Generate HTML report
generate_html_report() {
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

    cat "$TABLE_ROWS_FILE" >> cis_debian_report.html

    cat << EOF >> cis_debian_report.html
    </table>
</body>
</html>
EOF
    echo "HTML report generated: cis_debian_report.html"
}

# Run all checks
check_tmp_partition
check_ssh_config_permissions
check_ssh_protocol
check_apt_repos
check_auditd_service

# Generate report
generate_html_report

# Clean up
rm "$TABLE_ROWS_FILE"
