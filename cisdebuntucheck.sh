#!/bin/bash

# Function to prompt for user input and validate
prompt_user_input() {
    echo "Enter the operating system (Ubuntu or Debian):"
    read -r os
    os=$(echo "$os" | tr '[:upper:]' '[:lower:]')
    while [[ "$os" != "ubuntu" && "$os" != "debian" ]]; do
        echo "Invalid input. Please enter 'Ubuntu' or 'Debian':"
        read -r os
        os=$(echo "$os" | tr '[:upper:]' '[:lower:]')
    done
    OS="$os"

    echo "Enter the profile (Server or Workstation):"
    read -r profile
    profile=$(echo "$profile" | tr '[:upper:]' '[:lower:]')
    while [[ "$profile" != "server" && "$profile" != "workstation" ]]; do
        echo "Invalid input. Please enter 'Server' or 'Workstation':"
        read -r profile
        profile=$(echo "$profile" | tr '[:upper:]' '[:lower:]')
    done
    PROFILE="$profile"

    echo -e "\nThis script will scan the system for CIS benchmark compliance."
    echo "It requires root privileges and may modify log files in the current directory."
    echo "Do you consent to proceed? (yes/no)"
    read -r consent
    consent=$(echo "$consent" | tr '[:upper:]' '[:lower:]')
    if [[ "$consent" != "yes" ]]; then
        echo "Script execution aborted by user."
        exit 1
    fi
}

# Initialize counters
declare -A counters=(
    ["score_total"]=0 ["score_ok"]=0
    ["notscored_total"]=0 ["notscored_ok"]=0
)

# Check if terminal supports colors
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    NC=$(tput sgr0)
else
    RED='' GREEN='' YELLOW='' NC=''
fi

# Logging setup
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="./cis_benchmark_log_${TIMESTAMP}.log"
HTML_OUTPUT="./cis_benchmark_${TIMESTAMP}.html"
touch "$LOG_FILE" 2>/dev/null || { echo "Cannot write to current directory. Ensure write permissions."; exit 1; }
declare -a HTML_RESULTS

# Function to log messages
log_message() {
    local message="$1"
    echo -e "$message" | tee -a "$LOG_FILE"
}

# Function to determine risk rating based on reference and score
get_risk_rating() {
    local ref="$1" score="$2"
    if [[ "$score" == "Yes" ]]; then
        case "$ref" in
            1.*) echo "High" ;;    # Filesystem and partitioning
            4.*) echo "Medium" ;;  # Audit logging
            5.*) echo "High" ;;    # Access control and SSH
            *) echo "Medium" ;;
        esac
    else
        echo "Low"  # Not scored tests are advisory
    fi
}

# Function to determine fix type
get_fix_type() {
    local ref="$1" status="$2"
    if [[ "$status" == "PASS" ]]; then
        echo "N/A"
    else
        case "$ref" in
            1.1.*) echo "Involved" ;;  # Partitioning changes
            4.*) echo "Planned" ;;     # Audit configuration
            5.*) echo "Quick" ;;       # SSH and user config
            *) echo "Involved" ;;
        esac
    fi
}

# Function to determine remediation steps based on CIS Ubuntu 20.04 Benchmark
get_remediation() {
    local ref="$1" status="$2"
    if [[ "$status" == "PASS" ]]; then
        echo "No remediation required"
    else
        case "$ref" in
            1.1.1.1)
                echo "Run: echo 'install cramfs /bin/true' >> /etc/modprobe.d/cramfs.conf && modprobe -r cramfs"
                ;;
            1.1.1.2)
                echo "Run: echo 'install freevxfs /bin/true' >> /etc/modprobe.d/freevxfs.conf && modprobe -r freevxfs"
                ;;
            1.1.1.3)
                echo "Run: echo 'install jffs2 /bin/true' >> /etc/modprobe.d/jffs2.conf && modprobe -r jffs2"
                ;;
            1.1.1.4)
                echo "Run: echo 'install hfs /bin/true' >> /etc/modprobe.d/hfs.conf && modprobe -r hfs"
                ;;
            1.1.1.5)
                echo "Run: echo 'install hfsplus /bin/true' >> /etc/modprobe.d/hfsplus.conf && modprobe -r hfsplus"
                ;;
            1.1.1.6)
                echo "Run: echo 'install squashfs /bin/true' >> /etc/modprobe.d/squashfs.conf && modprobe -r squashfs"
                ;;
            1.1.1.7)
                echo "Run: echo 'install udf /bin/true' >> /etc/modprobe.d/udf.conf && modprobe -r udf"
                ;;
            1.1.1.8)
                echo "Run: echo 'install vfat /bin/true' >> /etc/modprobe.d/vfat.conf && modprobe -r vfat"
                ;;
            1.1.2)
                echo "Edit /etc/fstab to create a separate /tmp partition, e.g., 'tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec 0 0'"
                ;;
            1.1.3|1.1.4|1.1.5|1.1.8|1.1.9|1.1.10|1.1.14|1.1.16|1.1.17)
                echo "Edit /etc/fstab to add nodev, nosuid, or noexec options for the relevant partition (e.g., /tmp, /var/tmp, /home, /dev/shm)"
                ;;
            1.1.6|1.1.7|1.1.11|1.1.12|1.1.13)
                echo "Create a separate partition for /var, /var/tmp, /var/log, /var/log/audit, or /home during system setup or resize existing partitions"
                ;;
            1.1.15)
                echo "Edit /etc/fstab to add nodev option for /dev/shm, e.g., 'tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0'"
                ;;
            1.1.18|1.1.19|1.1.20)
                echo "Edit /etc/fstab to add nodev, nosuid, or noexec options for removable media partitions"
                ;;
            1.1.21)
                echo "Run: find / -type d -perm -0002 -exec chmod +t {} \;"
                ;;
            1.1.22)
                echo "Run: systemctl disable autofs && apt remove autofs"
                ;;
            1.2.1)
                echo "Configure repositories in /etc/apt/sources.list or /etc/apt/sources.list.d/ based on your organization's policy"
                ;;
            1.2.2)
                echo "Run: apt-key adv --keyserver keyserver.ubuntu.com --recv-keys <KEY_ID>"
                ;;
            1.2.3)
                echo "Edit /etc/apt/apt.conf.d/00local to include 'APT::Get::AllowUnauthenticated \"false\";'"
                ;;
            1.3.1)
                echo "Run: apt install aide aide-common && aideinit"
                ;;
            1.3.2)
                echo "Create a cron job, e.g., '0 5 * * * /usr/bin/aide.wrapper --check' in /etc/crontab"
                ;;
            1.4.1)
                echo "Run: chown root:root /boot/grub/grub.cfg && chmod og-rwx /boot/grub/grub.cfg"
                ;;
            1.4.2)
                echo "Edit /etc/grub.d/40_custom to add 'set superusers=\"root\"' and 'password_pbkdf2 root <hashed-password>', then run: update-grub"
                ;;
            1.4.3)
                echo "Run: systemctl edit rescue.service && systemctl edit emergency.service to set ExecStart with sulogin"
                ;;
            1.5.1)
                echo "Edit /etc/security/limits.conf to add '* hard core 0' and run: sysctl -w fs.suid_dumpable=0"
                ;;
            1.5.2)
                echo "Verify CPU NX support in /proc/cpuinfo or BIOS settings; no specific command for enabling"
                ;;
            1.5.3)
                echo "Run: sysctl -w kernel.randomize_va_space=2 && echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.conf"
                ;;
            1.5.4)
                echo "Run: apt remove prelink"
                ;;
            1.6.1.1)
                echo "Edit /etc/default/grub to remove 'selinux=0' or 'enforcing=0', then run: update-grub"
                ;;
            1.6.1.2)
                echo "Edit /etc/selinux/config to set SELINUX=enforcing"
                ;;
            1.6.1.3)
                echo "Edit /etc/selinux/config to set SELINUXTYPE=targeted or strict"
                ;;
            1.6.1.4)
                echo "Run: apt remove setroubleshoot"
                ;;
            1.6.1.5)
                echo "Run: apt remove mcstrans"
                ;;
            1.6.1.6)
                echo "Run: ps -eZ | grep unconfined_service_t and terminate or relabel unconfined processes"
                ;;
            1.6.2)
                echo "Run: apt install libselinux1"
                ;;
            1.7.1.1)
                echo "Edit /etc/motd to include appropriate legal notice"
                ;;
            1.7.1.2|1.7.1.3)
                echo "Edit /etc/issue or /etc/issue.net to include appropriate legal notice"
                ;;
            1.7.1.4)
                echo "Run: chown root:root /etc/motd && chmod 644 /etc/motd"
                ;;
            1.7.1.5)
                echo "Run: chown root:root /etc/issue && chmod 644 /etc/issue"
                ;;
            1.7.1.6)
                echo "Run: chown root:root /etc/issue.net && chmod 644 /etc/issue.net"
                ;;
            1.7.2)
                echo "Edit /etc/gdm3/greeter.dconf-defaults to set banner-message-enable=true and banner-message-text"
                ;;
            1.8)
                echo "Run: apt update && apt upgrade"
                ;;
            2.1.*|2.2.[2-21]|2.3.*)
                echo "Run: systemctl disable <service_name> && apt remove <package_name> (e.g., xinetd, avahi-daemon, cups)"
                ;;
            2.2.1.1)
                echo "Run: apt install chrony || apt install ntp"
                ;;
            2.2.1.2)
                echo "Edit /etc/ntp.conf to configure NTP servers and restrict access"
                ;;
            2.2.1.3)
                echo "Edit /etc/chrony/chrony.conf to configure time servers"
                ;;
            3.1.1|3.1.2|3.2.*)
                echo "Edit /etc/sysctl.conf to set net.ipv4.ip_forward=0, net.ipv4.conf.all.send_redirects=0, etc."
                ;;
            3.3.1|3.3.2|3.3.3)
                echo "Edit /etc/sysctl.conf to set net.ipv6.conf.all.accept_ra=0, net.ipv6.conf.all.disable_ipv6=1, etc."
                ;;
            3.4.1)
                echo "Run: apt install tcpd"
                ;;
            3.4.2|3.4.3)
                echo "Edit /etc/hosts.allow or /etc/hosts.deny to configure access rules"
                ;;
            3.4.4|3.4.5)
                echo "Run: chown root:root /etc/hosts.allow && chmod 644 /etc/hosts.allow (or /etc/hosts.deny)"
                ;;
            3.5.*)
                echo "Run: echo 'install <protocol> /bin/true' >> /etc/modprobe.d/<protocol>.conf && modprobe -r <protocol>"
                ;;
            3.6.1)
                echo "Run: apt install iptables"
                ;;
            3.6.2|3.6.3|3.6.5)
                echo "Configure iptables rules, e.g., iptables -P INPUT DROP, iptables -A INPUT -i lo -j ACCEPT"
                ;;
            3.6.4)
                echo "Configure iptables for outbound/established connections, e.g., iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"
                ;;
            3.7)
                echo "Run: nmcli radio wifi off || iwconfig wlan0 power off"
                ;;
            4.1.1.1)
                echo "Edit /etc/audit/auditd.conf to set max_log_file and max_log_file_action"
                ;;
            4.1.1.2)
                echo "Edit /etc/audit/auditd.conf to set space_left_action, action_mail_acct, admin_space_left_action"
                ;;
            4.1.1.3)
                echo "Edit /etc/audit/auditd.conf to set max_log_file_action=keep_logs"
                ;;
            4.1.2)
                echo "Run: systemctl enable auditd"
                ;;
            4.1.3)
                echo "Edit /etc/default/grub to add audit=1, then run: update-grub"
                ;;
            4.1.4|4.1.5|4.1.6|4.1.7|4.1.8|4.1.9|4.1.10|4.1.11|4.1.12|4.1.13|4.1.14|4.1.15|4.1.16|4.1.17)
                echo "Add audit rules to /etc/audit/rules.d/audit.rules, e.g., -a always,exit -F arch=b64 -S <syscall> -k <key>"
                ;;
            4.1.18)
                echo "Add -e 2 to /etc/audit/rules.d/audit.rules"
                ;;
            4.2.1.1)
                echo "Run: systemctl enable rsyslog"
                ;;
            4.2.1.2|4.2.2.2)
                echo "Edit /etc/rsyslog.conf or /etc/syslog-ng/syslog-ng.conf to configure logging"
                ;;
            4.2.1.3)
                echo "Edit /etc/rsyslog.conf to set FileCreateMode 0640"
                ;;
            4.2.1.4|4.2.2.4)
                echo "Edit /etc/rsyslog.conf or /etc/syslog-ng/syslog-ng.conf to configure remote logging"
                ;;
            4.2.1.5|4.2.2.5)
                echo "Edit /etc/rsyslog.conf or /etc/syslog-ng/syslog-ng.conf to restrict remote messages"
                ;;
            4.2.2.1)
                echo "Run: systemctl enable syslog-ng"
                ;;
            4.2.2.3)
                echo "Edit /etc/syslog-ng/syslog-ng.conf to set perm(0640)"
                ;;
            4.2.3)
                echo "Run: apt install rsyslog || apt install syslog-ng"
                ;;
            4.2.4)
                echo "Run: find /var/log -type f -exec chmod g-wx,o-rwx {} +"
                ;;
            4.3)
                echo "Edit /etc/logrotate.conf and /etc/logrotate.d/* to configure rotation policies"
                ;;
            5.1.*)
                echo "Run: chown root:root /etc/crontab /etc/cron.* && chmod og-rwx /etc/crontab /etc/cron.*"
                ;;
            5.2.1)
                echo "Run: chown root:root /etc/ssh/sshd_config && chmod og-rwx /etc/ssh/sshd_config"
                ;;
            5.2.2)
                echo "Edit /etc/ssh/sshd_config to set Protocol 2"
                ;;
            5.2.3)
                echo "Edit /etc/ssh/sshd_config to set LogLevel INFO"
                ;;
            5.2.4)
                echo "Edit /etc/ssh/sshd_config to set X11Forwarding no"
                ;;
            5.2.5)
                echo "Edit /etc/ssh/sshd_config to set MaxAuthTries 4"
                ;;
            5.2.6)
                echo "Edit /etc/ssh/sshd_config to set IgnoreRhosts yes"
                ;;
            5.2.7)
                echo "Edit /etc/ssh/sshd_config to set HostbasedAuthentication no"
                ;;
            5.2.8)
                echo "Edit /etc/ssh/sshd_config to set PermitRootLogin no"
                ;;
            5.2.9)
                echo "Edit /etc/ssh/sshd_config to set PermitEmptyPasswords no"
                ;;
            5.2.10)
                echo "Edit /etc/ssh/sshd_config to set PermitUserEnvironment no"
                ;;
            5.2.11)
                echo "Edit /etc/ssh/sshd_config to set MACs hmac-sha2-512,hmac-sha2-256"
                ;;
            5.2.12)
                echo "Edit /etc/ssh/sshd_config to set ClientAliveInterval 300, ClientAliveCountMax 0"
                ;;
            5.2.13)
                echo "Edit /etc/ssh/sshd_config to set LoginGraceTime 60"
                ;;
            5.2.14)
                echo "Edit /etc/ssh/sshd_config to set AllowUsers, AllowGroups, DenyUsers, or DenyGroups"
                ;;
            5.2.15)
                echo "Edit /etc/ssh/sshd_config to set Banner /etc/issue.net"
                ;;
            5.3.1)
                echo "Edit /etc/security/pwquality.conf to set minlen=14, dcredit=-1, ucredit=-1, ocredit=-1, lcredit=-1"
                ;;
            5.3.2)
                echo "Edit /etc/security/faillock.conf to set deny=5, unlock_time=900"
                ;;
            5.3.3)
                echo "Edit /etc/security/pwquality.conf to set remember=5"
                ;;
            5.3.4)
                echo "Edit /etc/login.defs to set PASS_ALGO sha512"
                ;;
            5.4.1.1)
                echo "Edit /etc/login.defs to set PASS_MAX_DAYS 365"
                ;;
            5.4.1.2)
                echo "Edit /etc/login.defs to set PASS_MIN_DAYS 7"
                ;;
            5.4.1.3)
                echo "Edit /etc/login.defs to set PASS_WARN_AGE 7"
                ;;
            5.4.1.4)
                echo "Run: useradd -D -f 30"
                ;;
            5.4.1.5)
                echo "Run: for user in \$(cut -d: -f1 /etc/passwd); do chage --lastday \$(date -d '-1 year' +%Y-%m-%d) \$user; done"
                ;;
            5.4.2)
                echo "Run: for user in \$(cut -d: -f1 /etc/passwd); do usermod -s /bin/false \$user; done (except valid login accounts)"
                ;;
            5.4.3)
                echo "Run: usermod -g 0 root"
                ;;
            5.4.4)
                echo "Edit /etc/login.defs to set UMASK 027"
                ;;
            5.4.5)
                echo "Edit /etc/profile or /etc/bash.bashrc to set TMOUT=900"
                ;;
            5.5)
                echo "Edit /etc/securetty to restrict root login to specific TTYs"
                ;;
            5.6)
                echo "Edit /etc/pam.d/su to add pam_wheel.so"
                ;;
            6.1.1)
                echo "Run: dpkg -l | grep -v '^ii' to audit package permissions"
                ;;
            6.1.[2-9])
                echo "Run: chown root:root /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow- && chmod 644 /etc/passwd /etc/group && chmod 600 /etc/shadow /etc/gshadow"
                ;;
            6.1.10)
                echo "Run: find / -type f -perm -o+w -exec chmod o-w {} \;"
                ;;
            6.1.11)
                echo "Run: find / -type f -nouser -exec chown root {} \;"
                ;;
            6.1.12)
                echo "Run: find / -type f -nogroup -exec chgrp root {} \;"
                ;;
            6.1.13|6.1.14)
                echo "Run: find / -perm /4000 -o -perm /2000 to list SUID/SGID files and review manually"
                ;;
            6.2.*)
                echo "Edit /etc/passwd, /etc/shadow, or /etc/group to remove invalid entries or duplicates"
                ;;
            *)
                echo "Review CIS ${OS^} Benchmark documentation for specific remediation steps for ${ref}"
                ;;
        esac
    fi
}

# Function to add to HTML results
add_html_result() {
    local ref="$1" status="$2" msg="$3" profile="$4"
    local risk_rating=$(get_risk_rating "$ref" "$score")
    local fix_type=$(get_fix_type "$ref" "$status")
    local remediation=$(get_remediation "$ref" "$status")
    HTML_RESULTS+=("<tr><td>${ref}</td><td>${msg}</td><td>${risk_rating}</td><td class=\"${status,,}\">${status}</td><td>${fix_type}</td><td>${remediation}</td></tr>")
}

# Function to generate HTML report
generate_html_report() {
    local hostname="$1"
    local timestamp="$2"
    local total_scored=${counters[score_total]}
    local total_notscored=${counters[notscored_total]}
    local passed_scored=${counters[score_ok]}
    local passed_notscored=${counters[notscored_ok]}
    local scored_pass_rate=$(awk "BEGIN {printf \"%.1f\", ${passed_scored}*100/${total_scored}}")
    local notscored_pass_rate=$(awk "BEGIN {printf \"%.1f\", ${passed_notscored}*100/${total_notscored}}")

    cat << EOF > "$HTML_OUTPUT"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS ${OS^} Benchmark Results</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-family: Arial, sans-serif; }
        .pass { color: green; }
        .fail { color: red; }
        .skip { color: orange; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        canvas { max-width: 800px; margin: 20px auto; }
    </style>
</head>
<body class="bg-gray-100 p-6">
    <div class="max-w-6xl mx-auto bg-white p-6 rounded-lg shadow-lg">
        <h1 class="text-2xl font-bold mb-4">CIS ${OS^} Benchmark Check</h1>
        <p><strong>Hostname:</strong> ${hostname}</p>
        <p><strong>Time:</strong> ${timestamp}</p>
        <p><strong>Operating System:</strong> ${OS^}</p>
        <p><strong>Profile:</strong> ${PROFILE^}</p>

        <h2 class="text-xl font-semibold mt-6 mb-2">Executive Summary</h2>
        <p>The CIS ${OS^} Benchmark assessment evaluated ${total_scored} scored and ${total_notscored} not scored tests for the ${PROFILE^} profile. The overall pass rate for scored tests is ${scored_pass_rate}%, indicating partial compliance with critical security controls. Not scored tests achieved a pass rate of ${notscored_pass_rate}%, reflecting advisory recommendations.</p>
        <ul class="list-disc pl-5 mb-4">
            <li><strong>Scored Tests:</strong> ${counters[score_ok]}/${counters[score_total]} (${scored_pass_rate}%) passed.</li>
            <li><strong>Not Scored Tests:</strong> ${counters[notscored_ok]}/${counters[notscored_total]} (${notscored_pass_rate}%) passed.</li>
        </ul>
        <p><strong>Recommendations:</strong> Prioritize remediation of failed scored tests, focusing on filesystem security (e.g., 1.1.1.1-1.1.1.8), partitioning (e.g., 1.1.6-1.1.13), and audit logging (e.g., 4.1.1.2-4.1.18). Review not scored test failures to align with security best practices.</p>

        <h2 class="text-xl font-semibold mt-6 mb-2">Summary</h2>
        <div class="grid grid-cols-2 gap-4 mb-6">
            <div>
                <h3 class="text-lg font-medium">Scored (${PROFILE^})</h3>
                <p>${counters[score_ok]} / ${counters[score_total]}</p>
            </div>
            <div>
                <h3 class="text-lg font-medium">Not Scored (${PROFILE^})</h3>
                <p>${counters[notscored_ok]} / ${counters[notscored_total]}</p>
            </div>
        </div>

        <h2 class="text-xl font-semibold mt-6 mb-2">Pass/Fail Distribution</h2>
        <canvas id="resultsChart"></canvas>

        <h2 class="text-xl font-semibold mt-6 mb-2">Detailed Test Results</h2>
        <table class="w-full mb-6">
            <thead>
                <tr>
                    <th>Finding ID</th>
                    <th>Issue Name</th>
                    <th>Risk-Rating</th>
                    <th>Status</th>
                    <th>Fix-Type</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                ${HTML_RESULTS[*]}
            </tbody>
        </table>
    </div>

    <script>
        const ctx = document.getElementById('resultsChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Scored (${PROFILE^})', 'Not Scored (${PROFILE^})'],
                datasets: [
                    {
                        label: 'Passed',
                        data: [${counters[score_ok]}, ${counters[notscored_ok]}],
                        backgroundColor: 'rgba(75, 192, 192, 0.6)',
                        borderColor: 'rgba(75, 192, 192, 1)',
                        borderWidth: 1
                    },
                    {
                        label: 'Failed',
                        data: [${counters[score_total]}-${counters[score_ok]}, ${counters[notscored_total]}-${counters[notscored_ok]}],
                        backgroundColor: 'rgba(255, 99, 132, 0.6)',
                        borderColor: 'rgba(255, 99, 132, 1)',
                        borderWidth: 1
                    }
                ]
            },
            options: {
                scales: {
                    y: { beginAtZero: true, title: { display: true, text: 'Number of Tests' } },
                    x: { title: { display: true, text: 'Category' } }
                },
                plugins: {
                    legend: { position: 'top' },
                    title: { display: true, text: 'CIS Benchmark Test Results' }
                }
            }
        });
    </script>
</body>
</html>
EOF
}

test_wrapper() {
    local ref="$1"
    local msg="$2"
    local score="$3"
    local server="$4"
    local workstation="$5"
    local profile="${server}, ${workstation}"

    # Skip test if it doesn't match the selected profile
    if [[ "$PROFILE" == "server" && ! "$server" =~ Server[12] ]] || [[ "$PROFILE" == "workstation" && ! "$workstation" =~ Workstation[12] ]]; then
        return
    fi

    # Update counters for totals
    if [[ "$score" == "Yes" ]]; then
        ((counters[score_total]++))
    else
        ((counters[notscored_total]++))
    fi

    if [[ -f "./test/${ref}.sh" ]]; then
        if ! bash "./test/${ref}.sh" > /dev/null 2>>"$LOG_FILE"; then
            log_message "${RED}FAIL${NC} - $ref - $msg"
            add_html_result "$ref" "FAIL" "$msg" "$profile"
        else
            log_message "${GREEN}PASS${NC} - $ref - $msg"
            add_html_result "$ref" "PASS" "$msg" "$profile"
            if [[ "$score" == "Yes" ]]; then
                ((counters[score_ok]++))
            else
                ((counters[notscored_ok]++))
            fi
        fi
    else
        log_message "${YELLOW}SKIP${NC} - $ref - $msg (Test script not found)"
        add_html_result "$ref" "SKIP" "$msg" "$profile"
    fi
}

# Check for root privileges
if [[ "$(id -u)" -ne 0 ]]; then
    log_message "Error: This script must be run as root"
    exit 1
fi

# Prompt for user input and consent
prompt_user_input

# Display banner
log_message "=================================================="
log_message "      CIS ${OS^} Benchmark Check"
log_message "      Version 2.0"
log_message "      Developed by Astra-X"
log_message "=================================================="

# Header
log_message ""
log_message "Hostname: $(hostname)"
log_message "Time: $(date)"
log_message "Operating System: ${OS^}"
log_message "Profile: ${PROFILE^}"
log_message "================================================================================="

# Define tests (same as original)
declare -a tests=(
    "1.1.1.1|Ensure mounting of cramfs filesystems is disabled (Scored)|Yes|Server1|Workstation1"
    "1.1.1.2|Ensure mounting of freevxfs filesystems is disabled (Scored)|Yes|Server1|Workstation1"
    "1.1.1.3|Ensure mounting of jffs2 filesystems is disabled (Scored)|Yes|Server1|Workstation1"
    "1.1.1.4|Ensure mounting of hfs filesystems is disabled (Scored)|Yes|Server1|Workstation1"
    "1.1.1.5|Ensure mounting of hfsplus filesystems is disabled (Scored)|Yes|Server1|Workstation1"
    "1.1.1.6|Ensure mounting of squashfs filesystems is disabled (Scored)|Yes|Server1|Workstation1"
    "1.1.1.7|Ensure mounting of udf filesystems is disabled (Scored)|Yes|Server1|Workstation1"
    "1.1.1.8|Ensure mounting of FAT filesystems is disabled (Scored)|Yes|Server2|Workstation2"
    "1.1.2|Ensure separate partition exists for /tmp (Scored)|Yes|Server2|Workstation2"
    "1.1.3|Ensure nodev option set on /tmp partition (Scored)|Yes|Server1|Workstation1"
    "1.1.4|Ensure nosuid option set on /tmp partition (Scored)|Yes|Server1|Workstation1"
    "1.1.5|Ensure noexec option set on /tmp partition (Scored)|Yes|Server1|Workstation1"
    "1.1.6|Ensure separate partition exists for /var (Scored)|Yes|Server2|Workstation2"
    "1.1.7|Ensure separate partition exists for /var/tmp (Scored)|Yes|Server2|Workstation2"
    "1.1.8|Ensure nodev option set on /var/tmp partition (Scored)|Yes|Server1|Workstation1"
    "1.1.9|Ensure nosuid option set on /var/tmp partition (Scored)|Yes|Server1|Workstation1"
    "1.1.10|Ensure noexec option set on /var/tmp partition (Scored)|Yes|Server1|Workstation1"
    "1.1.11|Ensure separate partition exists for /var/log (Scored)|Yes|Server2|Workstation2"
    "1.1.12|Ensure separate partition exists for /var/log/audit (Scored)|Yes|Server2|Workstation2"
    "1.1.13|Ensure separate partition exists for /home (Scored)|Yes|Server2|Workstation2"
    "1.1.14|Ensure nodev option set on /home partition (Scored)|Yes|Server1|Workstation1"
    "1.1.15|Ensure nodev option set on /dev/shm partition (Scored)|Yes|Server1|Workstation1"
    "1.1.16|Ensure nosuid option set on /dev/shm partition (Scored)|Yes|Server1|Workstation1"
    "1.1.17|Ensure noexec option set on /dev/shm partition (Scored)|Yes|Server1|Workstation1"
    "1.1.18|Ensure nodev option set on removable media partitions (Not Scored)|No|Server1|Workstation1"
    "1.1.19|Ensure nosuid option set on removable media partitions (Not Scored)|No|Server1|Workstation1"
    "1.1.20|Ensure noexec option set on removable media partitions (Not Scored)|No|Server1|Workstation1"
    "1.1.21|Ensure sticky bit is set on all world-writable directories (Scored)|Yes|Server1|Workstation1"
    "1.1.22|Disable Automounting (Scored)|Yes|Server1|Workstation2"
    "1.2.1|Ensure package manager repositories are configured (Not Scored)|No|Server1|Workstation1"
    "1.2.2|Ensure GPG keys are configured (Not Scored)|No|Server1|Workstation1"
    "1.2.3|Ensure gpgcheck is globally activated (Scored)|Yes|Server1|Workstation1"
    "1.3.1|Ensure AIDE is installed (Scored)|Yes|Server1|Workstation1"
    "1.3.2|Ensure filesystem integrity is regularly checked (Scored)|Yes|Server1|Workstation1"
    "1.4.1|Ensure permissions on bootloader config are configured (Scored)|Yes|Server1|Workstation1"
    "1.4.2|Ensure bootloader password is set (Scored)|Yes|Server1|Workstation1"
    "1.4.3|Ensure authentication required for single user mode (Scored)|Yes|Server1|Workstation1"
    "1.5.1|Ensure core dumps are restricted (Scored)|Yes|Server1|Workstation1"
    "1.5.2|Ensure XD/NX support is enabled (Not Scored)|No|Server1|Workstation1"
    "1.5.3|Ensure address space layout randomization (ASLR) is enabled (Scored)|Yes|Server1|Workstation1"
    "1.5.4|Ensure prelink is disabled (Scored)|Yes|Server1|Workstation1"
    "1.6.1.1|Ensure SELinux is not disabled in bootloader configuration (Scored)|Yes|Server2|Workstation2"
    "1.6.1.2|Ensure the SELinux state is enforcing (Scored)|Yes|Server2|Workstation2"
    "1.6.1.3|Ensure SELinux policy is configured (Scored)|Yes|Server2|Workstation2"
    "1.6.1.4|Ensure SETroubleshoot is not installed (Scored)|Yes|Server2|Workstation2"
    "1.6.1.5|Ensure the MCS Translation Service (mcstrans) is not installed (Scored)|Yes|Server2|Workstation2"
    "1.6.1.6|Ensure no unconfined daemons exist (Scored)|Yes|Server2|Workstation2"
    "1.6.2|Ensure SELinux is installed (Scored)|Yes|Server2|Workstation2"
    "1.7.1.1|Ensure message of the day is configured properly (Scored)|Yes|Server1|Workstation1"
    "1.7.1.2|Ensure local login warning banner is configured properly (Not Scored)|No|Server1|Workstation1"
    "1.7.1.3|Ensure remote login warning banner is configured properly (Not Scored)|No|Server1|Workstation1"
    "1.7.1.4|Ensure permissions on /etc/motd are configured (Not Scored)|No|Server1|Workstation1"
    "1.7.1.5|Ensure permissions on /etc/issue are configured (Scored)|Yes|Server1|Workstation1"
    "1.7.1.6|Ensure permissions on /etc/issue.net are configured (Not Scored)|No|Server1|Workstation1"
    "1.7.2|Ensure GDM login banner is configured (Scored)|Yes|Server1|Workstation1"
    "1.8|Ensure updates, patches, and additional security software are installed (Scored)|Yes|Server1|Workstation1"
    "2.1.1|Ensure chargen services are not enabled (Scored)|Yes|Server1|Workstation1"
    "2.1.2|Ensure daytime services are not enabled (Scored)|Yes|Server1|Workstation1"
    "2.1.3|Ensure discard services are not enabled (Scored)|Yes|Server1|Workstation1"
    "2.1.4|Ensure echo services are not enabled (Scored)|Yes|Server1|Workstation1"
    "2.1.5|Ensure time services are not enabled (Scored)|Yes|Server1|Workstation1"
    "2.1.6|Ensure tftp server is not enabled (Scored)|Yes|Server1|Workstation1"
    "2.1.7|Ensure xinetd is not enabled (Scored)|Yes|Server1|Workstation1"
    "2.2.1.1|Ensure time synchronization is in use (Not Scored)|No|Server1|Workstation1"
    "2.2.1.2|Ensure ntp is configured (Scored)|Yes|Server1|Workstation1"
    "2.2.1.3|Ensure chrony is configured (Scored)|Yes|Server1|Workstation1"
    "2.2.2|Ensure X Window System is not installed (Scored)|Yes|Server1|Workstation2"
    "2.2.3|Ensure Avahi Server is not enabled (Scored)|Yes|Server1|Workstation1"
    "2.2.4|Ensure CUPS is not enabled (Scored)|Yes|Server1|Workstation2"
    "2.2.5|Ensure DHCP Server is not enabled (Scored)|Yes|Server1|Workstation1"
    "2.2.6|Ensure LDAP server is not enabled (Scored)|Yes|Server1|Workstation1"
    "2.2.7|Ensure NFS and RPC are not enabled (Scored)|Yes|Server1|Workstation1"
    "2.2.8|Ensure DNS Server is not enabled (Scored)|Yes|Server1|Workstation1"
    "2.2.9|Ensure FTP Server is not enabled (Scored)|Yes|Server1|Workstation1"
    "2.2.10|Ensure HTTP server is not enabled (Scored)|Yes|Server1|Workstation1"
    "2.2.11|Ensure IMAP and POP3 server is not enabled (Scored)|Yes|Server1|Workstation1"
    "2.2.12|Ensure Samba is not enabled (Scored)|Yes|Server1|Workstation1"
    "2.2.13|Ensure HTTP Proxy Server is not enabled (Scored)|Yes|Server1|Workstation1"
    "2.2.14|Ensure SNMP Server is not enabled (Scored)|Yes|Server1|Workstation1"
    "2.2.15|Ensure mail transfer agent is configured for local-only mode (Scored)|Yes|Server1|Workstation1"
    "2.2.16|Ensure NIS Server is not enabled (Scored)|Yes|Server1|Workstation1"
    "2.2.17|Ensure rsh server is not enabled (Scored)|Yes|Server1|Workstation1"
    "2.2.18|Ensure telnet server is not enabled (Scored)|Yes|Server1|Workstation1"
    "2.2.19|Ensure tftp server is not enabled (Scored)|Yes|Server1|Workstation1"
    "2.2.20|Ensure rsync service is not enabled (Scored)|Yes|Server1|Workstation1"
    "2.2.21|Ensure talk server is not enabled (Scored)|Yes|Server1|Workstation1"
    "2.3.1|Ensure NIS Client is not installed (Scored)|Yes|Server1|Workstation1"
    "2.3.2|Ensure rsh client is not installed (Scored)|Yes|Server1|Workstation1"
    "2.3.3|Ensure talk client is not installed (Scored)|Yes|Server1|Workstation1"
    "2.3.4|Ensure telnet client is not installed (Scored)|Yes|Server1|Workstation1"
    "2.3.5|Ensure LDAP client is not installed (Scored)|Yes|Server1|Workstation1"
    "3.1.1|Ensure IP forwarding is disabled (Scored)|Yes|Server1|Workstation1"
    "3.1.2|Ensure packet redirect sending is disabled (Scored)|Yes|Server1|Workstation1"
    "3.2.1|Ensure source routed packets are not accepted (Scored)|Yes|Server1|Workstation1"
    "3.2.2|Ensure ICMP redirects are not accepted (Scored)|Yes|Server1|Workstation1"
    "3.2.3|Ensure secure ICMP redirects are not accepted (Scored)|Yes|Server1|Workstation1"
    "3.2.4|Ensure suspicious packets are logged (Scored)|Yes|Server1|Workstation1"
    "3.2.5|Ensure broadcast ICMP requests are ignored (Scored)|Yes|Server1|Workstation1"
    "3.2.6|Ensure bogus ICMP responses are ignored (Scored)|Yes|Server1|Workstation1"
    "3.2.7|Ensure Reverse Path Filtering is enabled (Scored)|Yes|Server1|Workstation1"
    "3.2.8|Ensure TCP SYN Cookies is enabled (Scored)|Yes|Server1|Workstation1"
    "3.3.1|Ensure IPv6 router advertisements are not accepted (Not Scored)|No|Server1|Workstation1"
    "3.3.2|Ensure IPv6 redirects are not accepted (Not Scored)|No|Server1|Workstation1"
    "3.3.3|Ensure IPv6 is disabled (Not Scored)|No|Server1|Workstation1"
    "3.4.1|Ensure TCP Wrappers is installed (Scored)|Yes|Server1|Workstation1"
    "3.4.2|Ensure /etc/hosts.allow is configured (Scored)|Yes|Server1|Workstation1"
    "3.4.3|Ensure /etc/hosts.deny is configured (Scored)|Yes|Server1|Workstation1"
    "3.4.4|Ensure permissions on /etc/hosts.allow are configured (Scored)|Yes|Server1|Workstation1"
    "3.4.5|Ensure permissions on /etc/hosts.deny are configured (Scored)|Yes|Server1|Workstation1"
    "3.5.1|Ensure DCCP is disabled (Not Scored)|No|Server1|Workstation1"
    "3.5.2|Ensure SCTP is disabled (Not Scored)|No|Server1|Workstation1"
    "3.5.3|Ensure RDS is disabled (Not Scored)|No|Server1|Workstation1"
    "3.5.4|Ensure TIPC is disabled (Not Scored)|No|Server1|Workstation1"
    "3.6.1|Ensure iptables is installed (Scored)|Yes|Server1|Workstation1"
    "3.6.2|Ensure default deny firewall policy (Scored)|Yes|Server1|Workstation1"
    "3.6.3|Ensure loopback traffic is configured (Scored)|Yes|Server1|Workstation1"
    "3.6.4|Ensure outbound and established connections are configured (Not Scored)|No|Server1|Workstation1"
    "3.6.5|Ensure firewall rules exist for all open ports (Scored)|Yes|Server1|Workstation1"
    "3.7|Ensure wireless interfaces are disabled (Not Scored)|No|Server1|Workstation2"
    "4.1.1.1|Ensure audit log storage size is configured (Not Scored)|No|Server2|Workstation2"
    "4.1.1.2|Ensure system is disabled when audit logs are full (Scored)|Yes|Server2|Workstation2"
    "4.1.1.3|Ensure audit logs are not automatically deleted (Scored)|Yes|Server2|Workstation2"
    "4.1.2|Ensure auditd service is enabled (Scored)|Yes|Server2|Workstation2"
    "4.1.3|Ensure auditing for processes that start prior to auditd is enabled (Scored)|Yes|Server2|Workstation2"
    "4.1.4|Ensure events that modify date and time information are collected (Scored)|Yes|Server2|Workstation2"
    "4.1.5|Ensure events that modify user/group information are collected (Scored)|Yes|Server2|Workstation2"
    "4.1.6|Ensure events that modify the system's network environment are collected (Scored)|Yes|Server2|Workstation2"
    "4.1.7|Ensure events that modify the system's Mandatory Access Controls are collected (Scored)|Yes|Server2|Workstation2"
    "4.1.8|Ensure login and logout events are collected (Scored)|Yes|Server2|Workstation2"
    "4.1.9|Ensure console initiation information is configured (Scored)|Yes|Server2|Workstation2"
    "4.1.10|Ensure discretionary access control permission modification events are collected (Scored)|Yes|Server2|Workstation2"
    "4.1.11|Ensure unsuccessful unauthorized file access attempts are collected (Scored)|Yes|Server2|Workstation2"
    "4.1.12|Ensure use of privileged commands is collected (Scored)|Yes|Server2|Workstation2"
    "4.1.13|Ensure successful file system mounts are collected (Scored)|Yes|Server2|Workstation2"
    "4.1.14|Ensure file deletion events by users are collected (Scored)|Yes|Server2|Workstation2"
    "4.1.15|Ensure changes to system administration scope (sudoers) is collected (Scored)|Yes|Server2|Workstation2"
    "4.1.16|Ensure system administrator actions (sudolog) is collected (Scored)|Yes|Server2|Workstation2"
    "4.1.17|Ensure kernel module loading and unloading is collected (Scored)|Yes|Server2|Workstation2"
    "4.1.18|Ensure the audit configuration is immutable (Scored)|Yes|Server2|Workstation2"
    "4.2.1.1|Ensure rsyslog Service is enabled (Scored)|Yes|Server1|Workstation1"
    "4.2.1.2|Ensure logging is configured (Not Scored)|No|Server1|Workstation1"
    "4.2.1.3|Ensure rsyslog default file permissions configured (Scored)|Yes|Server1|Workstation1"
    "4.2.1.4|Ensure rsyslog is configured to send logs to a remote log host (Scored)|Yes|Server1|Workstation1"
    "4.2.1.5|Ensure remote rsyslog messages are only accepted on designated log hosts. (Not Scored)|No|Server1|Workstation1"
    "4.2.2.1|Ensure syslog-ng service is enabled (Scored)|Yes|Server1|Workstation1"
    "4.2.2.2|Ensure logging is configured (Not Scored)|No|Server1|Workstation1"
    "4.2.2.3|Ensure syslog-ng default file permissions configured (Scored)|Yes|Server1|Workstation1"
    "4.2.2.4|Ensure syslog-ng is configured to send logs to a remote log host (Not Scored)|No|Server1|Workstation1"
    "4.2.2.5|Ensure remote syslog-ng messages are only accepted on designated log hosts (Not Scored)|No|Server1|Workstation1"
    "4.2.3|Ensure rsyslog or syslog-ng is installed (Scored)|Yes|Server1|Workstation1"
    "4.2.4|Ensure permissions on all logfiles are configured (Scored)|Yes|Server1|Workstation1"
    "4.3|Ensure logrotate is configured (Not Scored)|No|Server1|Workstation1"
    "5.1.1|Ensure cron daemon is enabled (Scored)|Yes|Server1|Workstation1"
    "5.1.2|Ensure permissions on /etc/crontab are configured (Scored)|Yes|Server1|Workstation1"
    "5.1.3|Ensure permissions on /etc/cron.hourly are configured (Scored)|Yes|Server1|Workstation1"
    "5.1.4|Ensure permissions on /etc/cron.daily are configured (Scored)|Yes|Server1|Workstation1"
    "5.1.5|Ensure permissions on /etc/cron.weekly are configured (Scored)|Yes|Server1|Workstation1"
    "5.1.6|Ensure permissions on /etc/cron.monthly are configured (Scored)|Yes|Server1|Workstation1"
    "5.1.7|Ensure permissions on /etc/cron.d are configured (Scored)|Yes|Server1|Workstation1"
    "5.1.8|Ensure at/cron is restricted to authorized users (Scored)|Yes|Server1|Workstation1"
    "5.2.1|Ensure permissions on /etc/ssh/sshd_config are configured (Scored)|Yes|Server1|Workstation1"
    "5.2.2|Ensure SSH Protocol is set to 2 (Scored)|Yes|Server1|Workstation1"
    "5.2.3|Ensure SSH LogLevel is set to INFO (Scored)|Yes|Server1|Workstation1"
    "5.2.4|Ensure SSH X11 forwarding is disabled (Scored)|Yes|Server1|Workstation1"
    "5.2.5|Ensure SSH MaxAuthTries is set to 4 or less (Scored)|Yes|Server1|Workstation1"
    "5.2.6|Ensure SSH IgnoreRhosts is enabled (Scored)|Yes|Server1|Workstation1"
    "5.2.7|Ensure SSH HostbasedAuthentication is disabled (Scored)|Yes|Server1|Workstation1"
    "5.2.8|Ensure SSH root login is disabled (Scored)|Yes|Server1|Workstation1"
    "5.2.9|Ensure SSH PermitEmptyPasswords is disabled (Scored)|Yes|Server1|Workstation1"
    "5.2.10|Ensure SSH PermitUserEnvironment is disabled (Scored)|Yes|Server1|Workstation1"
    "5.2.11|Ensure only approved MAC algorithms are used (Scored)|Yes|Server1|Workstation1"
    "5.2.12|Ensure SSH Idle Timeout Interval is configured (Scored)|Yes|Server1|Workstation1"
    "5.2.13|Ensure SSH LoginGraceTime is set to one minute or less (Scored)|Yes|Server1|Workstation1"
    "5.2.14|Ensure SSH access is limited (Scored)|Yes|Server1|Workstation1"
    "5.2.15|Ensure SSH warning banner is configured (Scored)|Yes|Server1|Workstation1"
    "5.3.1|Ensure password creation requirements are configured (Scored)|Yes|Server1|Workstation1"
    "5.3.2|Ensure lockout for failed password attempts is configured (Scored)|Yes|Server1|Workstation1"
    "5.3.3|Ensure password reuse is limited (Scored)|Yes|Server1|Workstation1"
    "5.3.4|Ensure password hashing algorithm is SHA-512 (Scored)|Yes|Server1|Workstation1"
    "5.4.1.1|Ensure password expiration is 365 days or less (Scored)|Yes|Server1|Workstation1"
    "5.4.1.2|Ensure minimum days between password changes is 7 or more (Scored)|Yes|Server1|Workstation1"
    "5.4.1.3|Ensure password expiration warning days is 7 or more (Scored)|Yes|Server1|Workstation1"
    "5.4.1.4|Ensure inactive password lock is 30 days or less (Scored)|Yes|Server1|Workstation1"
    "5.4.1.5|Ensure all users last password change date is in the past (Scored)|Yes|Server1|Workstation1"
    "5.4.2|Ensure system accounts are non-login (Scored)|Yes|Server1|Workstation1"
    "5.4.3|Ensure default group for the root account is GID 0 (Scored)|Yes|Server1|Workstation1"
    "5.4.4|Ensure default user umask is 027 or more restrictive (Scored)|Yes|Server1|Workstation1"
    "5.4.5|Ensure default user shell timeout is 900 seconds or less (Scored)|Yes|Server2|Workstation2"
    "5.5|Ensure root login is restricted to system console (Not Scored)|No|Server1|Workstation1"
    "5.6|Ensure access to the su command is restricted (Scored)|Yes|Server1|Workstation1"
    "6.1.1|Audit system file permissions (Not Scored)|No|Server2|Workstation2"
    "6.1.2|Ensure permissions on /etc/passwd are configured (Scored)|Yes|Server1|Workstation1"
    "6.1.3|Ensure permissions on /etc/shadow are configured (Scored)|Yes|Server1|Workstation1"
    "6.1.4|Ensure permissions on /etc/group are configured (Scored)|Yes|Server1|Workstation1"
    "6.1.5|Ensure permissions on /etc/gshadow are configured (Scored)|Yes|Server1|Workstation1"
    "6.1.6|Ensure permissions on /etc/passwd- are configured (Scored)|Yes|Server1|Workstation1"
    "6.1.7|Ensure permissions on /etc/shadow- are configured (Scored)|Yes|Server1|Workstation1"
    "6.1.8|Ensure permissions on /etc/group- are configured (Scored)|Yes|Server1|Workstation1"
    "6.1.9|Ensure permissions on /etc/gshadow- are configured (Scored)|Yes|Server1|Workstation1"
    "6.1.10|Ensure no world writable files exist (Scored)|Yes|Server1|Workstation1"
    "6.1.11|Ensure no unowned files or directories exist (Scored)|Yes|Server1|Workstation1"
    "6.1.12|Ensure no ungrouped files or directories exist (Scored)|Yes|Server1|Workstation1"
    "6.1.13|Audit SUID executables (Not Scored)|No|Server1|Workstation1"
    "6.1.14|Audit SGID executables (Not Scored)|No|Server1|Workstation1"
    "6.2.1|Ensure password fields are not empty (Scored)|Yes|Server1|Workstation1"
    "6.2.2|Ensure no legacy + entries exist in /etc/passwd (Scored)|Yes|Server1|Workstation1"
    "6.2.3|Ensure no legacy + entries exist in /etc/shadow (Scored)|Yes|Server1|Workstation1"
    "6.2.4|Ensure no legacy + entries exist in /etc/group (Scored)|Yes|Server1|Workstation1"
    "6.2.5|Ensure root is the only UID 0 account (Scored)|Yes|Server1|Workstation1"
    "6.2.6|Ensure root PATH Integrity (Scored)|Yes|Server1|Workstation1"
    "6.2.7|Ensure all users' home directories exist (Scored)|Yes|Server1|Workstation1"
    "6.2.8|Ensure users' home directories permissions are 750 or more restrictive (Scored)|Yes|Server1|Workstation1"
    "6.2.9|Ensure users own their home directories (Scored)|Yes|Server1|Workstation1"
    "6.2.10|Ensure users' dot files are not group or world writable (Scored)|Yes|Server1|Workstation1"
    "6.2.11|Ensure no users have .forward files (Scored)|Yes|Server1|Workstation1"
    "6.2.12|Ensure no users have .netrc files (Scored)|Yes|Server1|Workstation1"
    "6.2.13|Ensure users' .netrc Files are not group or world accessible (Scored)|Yes|Server1|Workstation1"
    "6.2.14|Ensure no users have .rhosts files (Scored)|Yes|Server1|Workstation1"
    "6.2.15|Ensure all groups in /etc/passwd exist in /etc/group (Scored)|Yes|Server1|Workstation1"
    "6.2.16|Ensure no duplicate UIDs exist (Scored)|Yes|Server1|Workstation1"
    "6.2.17|Ensure no duplicate GIDs exist (Scored)|Yes|Server1|Workstation1"
    "6.2.18|Ensure no duplicate user names exist (Scored)|Yes|Server1|Workstation1"
    "6.2.19|Ensure no duplicate group names exist (Scored)|Yes|Server1|Workstation1"
)

# Run tests
for test in "${tests[@]}"; do
    IFS='|' read -r ref msg score server workstation <<< "$test"
    test_wrapper "$ref" "$msg" "$score" "$server" "$workstation"
done

# Output console summary
log_message ""
log_message "Results"
log_message "===================================="
log_message "Scored (${PROFILE^})"
log_message "${counters[score_ok]} / ${counters[score_total]}"
log_message ""
log_message "Not Scored (${PROFILE^})"
log_message "${counters[notscored_ok]} / ${counters[notscored_total]}"

# Generate HTML report
generate_html_report "$(hostname)" "$(date)"
log_message "HTML report saved to $HTML_OUTPUT"
log_message "Log file: $LOG_FILE"
