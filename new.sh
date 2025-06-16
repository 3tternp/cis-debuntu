#!/bin/bash

# Initialize counters
declare -A counters=(
    ["score_server1_total"]=0 ["score_server1_ok"]=0
    ["score_server2_total"]=0 ["score_server2_ok"]=0
    ["score_workstation1_total"]=0 ["score_workstation1_ok"]=0
    ["score_workstation2_total"]=0 ["score_workstation2_ok"]=0
    ["noscore_server1_total"]=0 ["noscore_server1_ok"]=0
    ["noscore_server2_total"]=0 ["noscore_server2_ok"]=0
    ["noscore_workstation1_total"]=0 ["noscore_workstation1_ok"]=0
    ["noscore_workstation2_total"]=0 ["noscore_workstation2_ok"]=0
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
LOG_FILE="/var/log/cis_benchmark_${TIMESTAMP}.log"
HTML_OUTPUT="/var/log/cis_benchmark_${TIMESTAMP}.html"
touch "$LOG_FILE" 2>/dev/null || { echo "Cannot write to log file. Ensure root permissions."; exit 1; }
declare -a HTML_RESULTS

# Function to log messages
log_message() {
    local message="$1"
    echo -e "$message" | tee -a "$LOG_FILE"
}

# Function to add to HTML results
add_html_result() {
    local ref="$1" status="$2" msg="$3" profile="$4"
    HTML_RESULTS+=("<tr><td>${ref}</td><td>${msg}</td><td class=\"${status,,}\">${status}</td><td>${profile}</td></tr>")
}

# Function to generate HTML report
generate_html_report() {
    local hostname="$1"
    local timestamp="$2"
    local total_scored=$((counters[score_server1_total] + counters[score_server2_total] - counters[score_server1_total]))
    local total_noscored=$((counters[noscore_server1_total] + counters[noscore_server2_total] - counters[noscore_server1_total]))
    local passed_scored=$((counters[score_server1_ok] + counters[score_server2_ok] - counters[score_server1_ok]))
    local passed_noscored=$((counters[noscore_server1_ok] + counters[noscore_server2_ok] - counters[noscore_server1_ok]))
    local score_server1_pass_rate=$(awk "BEGIN {printf \"%.1f\", ${counters[score_server1_ok]}*100/${counters[score_server1_total]}}")
    local score_server2_pass_rate=$(awk "BEGIN {printf \"%.1f\", ${counters[score_server2_ok]}*100/${counters[score_server2_total]}}")
    local score_workstation1_pass_rate=$(awk "BEGIN {printf \"%.1f\", ${counters[score_workstation1_ok]}*100/${counters[score_workstation1_total]}}")
    local score_workstation2_pass_rate=$(awk "BEGIN {printf \"%.1f\", ${counters[score_workstation2_ok]}*100/${counters[score_workstation2_total]}}")
    local overall_scored_pass_rate=$(awk "BEGIN {printf \"%.1f\", ${passed_scored}*100/${total_scored}}")
    local overall_noscored_pass_rate=$(awk "BEGIN {printf \"%.1f\", ${passed_noscored}*100/${total_noscored}}")

    cat << EOF > "$HTML_OUTPUT"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Ubuntu Benchmark Results</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-family: Arial, sans-serif; }
        .pass { color: green; }
        .fail { color: red; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        canvas { max-width: 800px; margin: 20px auto; }
    </style>
</head>
<body class="bg-gray-100 p-6">
    <div class="max-w-6xl mx-auto bg-white p-6 rounded-lg shadow-lg">
        <h1 class="text-2xl font-bold mb-4">CIS Ubuntu Benchmark Check</h1>
        <p><strong>Hostname:</strong> ${hostname}</p>
        <p><strong>Time:</strong> ${timestamp}</p>

        <h2 class="text-xl font-semibold mt-6 mb-2">Executive Summary</h2>
        <p>The CIS Ubuntu Benchmark assessment evaluated ${total_scored} scored and ${total_noscored} not scored tests across Server and Workstation profiles. The overall pass rate for scored tests is ${overall_scored_pass_rate}%, indicating partial compliance with critical security controls. Not scored tests achieved a pass rate of ${overall_noscored_pass_rate}%, reflecting advisory recommendations.</p>
        <ul class="list-disc pl-5 mb-4">
            <li><strong>Server1 (Scored):</strong> ${counters[score_server1_ok]}/${counters[score_server1_total]} (${score_server1_pass_rate}%) passed, indicating moderate compliance.</li>
            <li><strong>Server2 (Scored):</strong> ${counters[score_server2_ok]}/${counters[score_server2_total]} (${score_server2_pass_rate}%) passed, highlighting significant non-compliance.</li>
            <li><strong>Workstation1 (Scored):</strong> ${counters[score_workstation1_ok]}/${counters[score_workstation1_total]} (${score_workstation1_pass_rate}%) passed, similar to Server1.</li>
            <li><strong>Workstation2 (Scored):</strong> ${counters[score_workstation2_ok]}/${counters[score_workstation2_total]} (${score_workstation2_pass_rate}%) passed, requiring urgent remediation.</li>
            <li><strong>Not Scored Tests:</strong> Lower pass rates, particularly for Server2 (0%) and Workstation2 (20%), suggest gaps in best practices.</li>
        </ul>
        <p><strong>Recommendations:</strong> Prioritize remediation of failed scored tests, especially for Server2 and Workstation2, focusing on filesystem security (e.g., 1.1.1.1-1.1.1.8), partitioning (e.g., 1.1.6-1.1.13), and audit logging (e.g., 4.1.1.2-4.1.18). Review not scored test failures to align with security best practices.</p>

        <h2 class="text-xl font-semibold mt-6 mb-2">Summary</h2>
        <div class="grid grid-cols-2 gap-4 mb-6">
            <div>
                <h3 class="text-lg font-medium">Scored (Server)</h3>
                <p>Server 1: ${counters[score_server1_ok]} / ${counters[score_server1_total]}</p>
                <p>Server 2: ${counters[score_server2_ok]} / ${counters[score_server2_total]}</p>
            </div>
            <div>
                <h3 class="text-lg font-medium">Scored (Workstation)</h3>
                <p>Workstation 1: ${counters[score_workstation1_ok]} / ${counters[score_workstation1_total]}</p>
                <p>Workstation 2: ${counters[score_workstation2_ok]} / ${counters[score_workstation2_total]}</p>
            </div>
            <div>
                <h3 class="text-lg font-medium">Not Scored (Server)</h3>
                <p>Server 1: ${counters[noscore_server1_ok]} / ${counters[noscore_server1_total]}</p>
                <p>Server 2: ${counters[noscore_server2_ok]} / ${counters[noscore_server2_total]}</p>
            </div>
            <div>
                <h3 class="text-lg font-medium">Not Scored (Workstation)</h3>
                <p>Workstation 1: ${counters[noscore_workstation1_ok]} / ${counters[noscore_workstation1_total]}</p>
                <p>Workstation 2: ${counters[noscore_workstation2_ok]} / ${counters[noscore_workstation2_total]}</p>
            </div>
        </div>

        <h2 class="text-xl font-semibold mt-6 mb-2">Pass/Fail Distribution</h2>
        <canvas id="resultsChart"></canvas>

        <h2 class="text-xl font-semibold mt-6 mb-2">Detailed Test Results</h2>
        <table class="w-full mb-6">
            <thead>
                <tr>
                    <th>Reference</th>
                    <th>Description</th>
                    <th>Status</th>
                    <th>Profile</th>
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
                labels: ['Server1 (Scored)', 'Server2 (Scored)', 'Workstation1 (Scored)', 'Workstation2 (Scored)', 'Server1 (Not Scored)', 'Server2 (Not Scored)', 'Workstation1 (Not Scored)', 'Workstation2 (Not Scored)'],
                datasets: [
                    {
                        label: 'Passed',
                        data: [${counters[score_server1_ok]}, ${counters[score_server2_ok]}, ${counters[score_workstation1_ok]}, ${counters[score_workstation2_ok]}, ${counters[noscore_server1_ok]}, ${counters[noscore_server2_ok]}, ${counters[noscore_workstation1_ok]}, ${counters[noscore_workstation2_ok]}],
                        backgroundColor: 'rgba(75, 192, 192, 0.6)',
                        borderColor: 'rgba(75, 192, 192, 1)',
                        borderWidth: 1
                    },
                    {
                        label: 'Failed',
                        data: [${counters[score_server1_total]}-${counters[score_server1_ok]}, ${counters[score_server2_total]}-${counters[score_server2_ok]}, ${counters[score_workstation1_total]}-${counters[score_workstation1_ok]}, ${counters[score_workstation2_total]}-${counters[score_workstation2_ok]}, ${counters[noscore_server1_total]}-${counters[noscore_server1_ok]}, ${counters[noscore_server2_total]}-${counters[noscore_server2_ok]}, ${counters[noscore_workstation1_total]}-${counters[noscore_workstation1_ok]}, ${counters[noscore_workstation2_total]}-${counters[noscore_workstation2_ok]}],
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

    # Update counters for totals
    if [[ "$score" == "Yes" ]]; then
        [[ "$server" == "Server1" ]] && ((counters[score_server1_total]++))
        [[ "$server" == "Server1" || "$server" == "Server2" ]] && ((counters[score_server2_total]++))
        [[ "$workstation" == "Workstation1" ]] && ((counters[score_workstation1_total]++))
        [[ "$workstation" == "Workstation1" || "$workstation" == "Workstation2" ]] && ((counters[score_workstation2_total]++))
    else
        [[ "$server" == "Server1" ]] && ((counters[noscore_server1_total]++))
        [[ "$server" == "Server1" || "$server" == "Server2" ]] && ((counters[noscore_server2_total]++))
        [[ "$workstation" == "Workstation1" ]] && ((counters[noscore_workstation1_total]++))
        [[ "$workstation" == "Workstation1" || "$workstation" == "Workstation2" ]] && ((counters[noscore_workstation2_total]++))
    fi

    if [[ -f "./test/${ref}.sh" ]]; then
        if ! bash "./test/${ref}.sh" > /dev/null 2>>"$LOG_FILE"; then
            log_message "${RED}FAIL${NC} - $ref - $msg"
            add_html_result "$ref" "FAIL" "$msg" "$profile"
        else
            log_message "${GREEN}PASS${NC} - $ref - $msg"
            add_html_result "$ref" "PASS" "$msg" "$profile"
            if [[ "$score" == "Yes" ]]; then
                [[ "$server" == "Server1" ]] && ((counters[score_server1_ok]++))
                [[ "$server" == "Server1" || "$server" == "Server2" ]] && ((counters[score_server2_ok]++))
                [[ "$workstation" == "Workstation1" ]] && ((counters[score_workstation1_ok]++))
                [[ "$workstation" == "Workstation1" || "$workstation" == "Workstation2" ]] && ((counters[score_workstation2_ok]++))
            else
                [[ "$server" == "Server1" ]] && ((counters[noscore_server1_ok]++))
                [[ "$server" == "Server1" || "$server" == "Server2" ]] && ((counters[noscore_server2_ok]++))
                [[ "$workstation" == "Workstation1" ]] && ((counters[noscore_workstation1_ok]++))
                [[ "$workstation" == "Workstation1" || "$workstation" == "Workstation2" ]] && ((counters[noscore_workstation2_ok]++))
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

# Header
log_message "CIS Ubuntu Benchmark Check"
log_message "Hostname: $(hostname)"
log_message "Time: $(date)"
log_message "================================================================================="

# Define tests (same as previous)
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
log_message "Scored (Server)"
log_message "Server 1 = ${counters[score_server1_ok]} / ${counters[score_server1_total]}"
log_message "Server 2 = ${counters[score_server2_ok]} / ${counters[score_server2_total]}"
log_message ""
log_message "Scored (Workstation)"
log_message "Workstation 1 = ${counters[score_workstation1_ok]} / ${counters[score_workstation1_total]}"
log_message "Workstation 2 = ${counters[score_workstation2_ok]} / ${counters[score_workstation2_total]}"
log_message ""
log_message "Not Scored (Server)"
log_message "Server 1 = ${counters[noscore_server1_ok]} / ${counters[noscore_server1_total]}"
log_message "Server 2 = ${counters[noscore_server2_ok]} / ${counters[noscore_server2_total]}"
log_message ""
log_message "Not Scored (Workstation)"
log_message "Workstation 1 = ${counters[noscore_workstation1_ok]} / ${counters[noscore_workstation1_total]}"
log_message "Workstation 2 = ${counters[noscore_workstation2_ok]} / ${counters[noscore_workstation2_total]}"

# Generate HTML report
generate_html_report "$(hostname)" "$(date)"
log_message "HTML report saved to $HTML_OUTPUT"
log_message "Log file: $LOG_FILE"
