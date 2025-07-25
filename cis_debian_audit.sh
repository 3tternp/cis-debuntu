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
    issue_name=$(echo "$issue_name" | sed 's/&/\&/g; s/</\</g; s/>/\>/g; s/"/\"/g; s/'\''/\'/g')
    remediation=$(echo "$remediation" | sed 's/&/\&/g; s/</\</g; s/>/\>/g; s/"/\"/g; s/'\''/\'/g')
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

# Check 2: Ensure nodev option set on /tmp partition
check_tmp_nodev() {
    if mount | grep /tmp | grep -q nodev; then
        add_result "1.1.1.2" "Ensure nodev option set on /tmp partition" "Pass" "Medium" "Quick" "Add nodev option to /tmp in /etc/fstab and remount."
    else
        add_result "1.1.1.2" "Ensure nodev option set on /tmp partition" "Fail" "Medium" "Quick" "Add nodev option to /tmp in /etc/fstab and remount."
    fi
}

# Check 3: Ensure nosuid option set on /tmp partition
check_tmp_nosuid() {
    if mount | grep /tmp | grep -q nosuid; then
        add_result "1.1.1.3" "Ensure nosuid option set on /tmp partition" "Pass" "Medium" "Quick" "Add nosuid option to /tmp in /etc/fstab and remount."
    else
        add_result "1.1.1.3" "Ensure nosuid option set on /tmp partition" "Fail" "Medium" "Quick" "Add nosuid option to /tmp in /etc/fstab and remount."
    fi
}

# Check 4: Ensure noexec option set on /tmp partition
check_tmp_noexec() {
    if mount | grep /tmp | grep -q noexec; then
        add_result "1.1.1.4" "Ensure noexec option set on /tmp partition" "Pass" "Medium" "Quick" "Add noexec option to /tmp in /etc/fstab and remount."
    else
        add_result "1.1.1.4" "Ensure noexec option set on /tmp partition" "Fail" "Medium" "Quick" "Add noexec option to /tmp in /etc/fstab and remount."
    fi
}

# Check 5: Ensure /var is a separate partition
check_var_partition() {
    if mountpoint -q /var; then
        add_result "1.1.2.1" "Ensure /var is configured as a separate partition" "Pass" "High" "Involved" "Configure /var as a separate partition in /etc/fstab."
    else
        add_result "1.1.2.1" "Ensure /var is configured as a separate partition" "Fail" "High" "Involved" "Configure /var as a separate partition in /etc/fstab."
    fi
}

# Check 6: Ensure /var/log is a separate partition
check_var_log_partition() {
    if mountpoint -q /var/log; then
        add_result "1.1.3.1" "Ensure /var/log is configured as a separate partition" "Pass" "High" "Involved" "Configure /var/log as a separate partition in /etc/fstab."
    else
        add_result "1.1.3.1" "Ensure /var/log is configured as a separate partition" "Fail" "High" "Involved" "Configure /var/log as a separate partition in /etc/fstab."
    fi
}

# Check 7: Ensure permissions on /etc/ssh/sshd_config are configured
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

# Check 8: Ensure SSH Protocol is set to 2
check_ssh_protocol() {
    if grep -q "^Protocol 2" /etc/ssh/sshd_config 2>/dev/null; then
        add_result "5.2.2" "Ensure SSH Protocol is set to 2" "Pass" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'Protocol 2'. Restart sshd: systemctl restart sshd"
    else
        add_result "5.2.2" "Ensure SSH Protocol is set to 2" "Fail" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'Protocol 2'. Restart sshd: systemctl restart sshd"
    fi
}

# Check 9: Ensure SSH LogLevel is set to INFO
check_ssh_loglevel() {
    if grep -q "^LogLevel INFO" /etc/ssh/sshd_config 2>/dev/null; then
        add_result "5.2.3" "Ensure SSH LogLevel is set to INFO" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'LogLevel INFO'. Restart sshd."
    else
        add_result "5.2.3" "Ensure SSH LogLevel is set to INFO" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'LogLevel INFO'. Restart sshd."
    fi
}

# Check 10: Ensure SSH MaxAuthTries is set to 4 or less
check_ssh_maxauthtries() {
    if grep -q "^MaxAuthTries [1-4]" /etc/ssh/sshd_config 2>/dev/null; then
        add_result "5.2.4" "Ensure SSH MaxAuthTries is set to 4 or less" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'MaxAuthTries 4'. Restart sshd."
    else
        add_result "5.2.4" "Ensure SSH MaxAuthTries is set to 4 or less" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'MaxAuthTries 4'. Restart sshd."
    fi
}

# Check 11: Ensure SSH PermitRootLogin is disabled
check_ssh_permitrootlogin() {
    if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null; then
        add_result "5.2.5 " "Ensure SSH PermitRootLogin is disabled" "Pass" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'PermitRootLogin no'. Restart sshd."
    else
        add_result "5.2.5" "Ensure SSH PermitRootLogin is disabled" "Fail" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'PermitRootLogin no'. Restart sshd."
    fi
}

# Check 12: Ensure SSH PermitEmptyPasswords is disabled
check_ssh_permitemptypasswords() {
    if grep -q "^PermitEmptyPasswords no" /etc/ssh/sshd_config 2>/dev/null; then
        add_result "5.2.6" "Ensure SSH PermitEmptyPasswords is disabled" "Pass" "High" "Quick " "Edit /etc/ssh/sshd_config and set 'PermitEmptyPasswords no'. Restart sshd."
    else
        add_result "5.2.6" "Ensure SSH PermitEmptyPasswords is disabled" "Fail" "High" "Quick" "Edit /etc/ssh/sshd_config and set 'PermitEmptyPasswords no'. Restart sshd."
    fi
}

# Check 13: Ensure package manager repositories are configured
check_apt_repos() {
    if apt update >/dev/null 2>&1; then
        add_result "3.1.2" "Ensure package manager repositories are configured" "Pass" "Low" "Planned" "Configure valid repositories in /etc/apt/sources.list and ensure they are accessible."
    else
        add_result "3.1.2" "Ensure package manager repositories are configured" "Fail" "Low" "Planned" "Configure valid repositories in /etc/apt/sources.list and ensure they are accessible."
    fi
}

# Check 14: Ensure auditd service is enabled
check_auditd_service() {
    if systemctl is-enabled auditd >/dev/null 2>&1; then
        add_result "4.1.1" "Ensure auditd service is enabled" "Pass" "Critical" "Quick" "Run: apt install auditd; systemctl enable auditd; systemctl start auditd"
    else
        add_result "4.1.1" "Ensure auditd service is enabled" "Fail" "Critical" "Quick" "Run: apt install auditd; systemctl enable auditd; systemctl start auditd"
    fi
}

# Check 15: Ensure permissions on /etc/passwd are configured
check_passwd_permissions() {
    local perms
    local owner
    local group
    perms=$(stat -c "%a" /etc/passwd 2>/dev/null)
    owner=$(stat -c "%U" /etc/passwd 2>/dev/null)
    group=$(stat -c "%G" /etc/passwd 2>/dev/null)
    if [ "$perms" = "644" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        add_result "5.4.1" "Ensure permissions on /etc/passwd are configured" "Pass" "Medium" "Quick" "Run: chmod 644 /etc/passwd; chown root:root /etc/passwd"
    else
        add_result "5.4.1" "Ensure permissions on /etc/passwd are configured" "Fail" "Medium" "Quick" "Run: chmod 644 /etc/passwd; chown root:root /etc/passwd"
    fi
}

# Check 16: Ensure permissions on /etc/shadow are configured
check_shadow_permissions() {
    local perms
    local owner
    local group
    perms=$(stat -c "%a" /etc/shadow 2>/dev/null)
    owner=$(stat -c "%U" /etc/shadow 2>/dev/null)
    group=$(stat -c "%G" /etc/shadow 2>/dev/null)
    if [ "$perms" = "640" ] && [ "$owner" = "root" ] && [ "$group" = "shadow" ]; then
        add_result "5.4.2" "Ensure permissions on /etc/shadow are configured" "Pass" "High" "Quick" "Run: chmod 640 /etc/shadow; chown root:shadow /etc/shadow"
    else
        add_result "5.4.2" "Ensure permissions on /etc/shadow are configured" "Fail" "High" "Quick" "Run: chmod 640 /etc/shadow; chown root:shadow /etc/shadow"
    fi
}

# Check 17: Ensure permissions on /etc/group are configured
check_group_permissions() {
    local perms
    local owner
    local group
    perms=$(stat -c "%a" /etc/group 2>/dev/null)
    owner=$(stat -c "%U" /etc/group 2>/dev/null)
    group全世界
    group=$(stat -c "%G" /etc/group 2>/dev/null)
    if [ "$perms" = "644" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        add_result "5.4.3" "Ensure permissions on /etc/group are configured" "Pass" "Medium" "Quick" "Run: chmod 644 /etc/group; chown root:root /etc/group"
    else
        add_result "5.4.3" "Ensure permissions on /etc/group are configured" "Fail" "Medium" "Quick" "Run: chmod 644 /etc/group; chown root:root /etc/group"
    fi
}

# Check 18: Ensure permissions on /etc/gshadow are configured
check_gshadow_permissions() {
    local perms
    local owner
    local group
    perms=$(stat -c "%a" /etc/gshadow 2>/dev/null)
    owner=$(stat -c "%U" /etc/gshadow 2>/dev/null)
    group=$(stat -c "%G" /etc/gshadow 2>/dev/null)
    if [ "$perms" = "640" ] && [ "$owner" = "root" ] && [ "$group" = "shadow" ]; then
        add_result "5.4.4" "Ensure permissions on /etc/gshadow are configured" "Pass" "High" "Quick" "Run: chmod 640 /etc/gshadow; chown root:shadow /etc/gshadow"
    else
        add_result "5.4.4" "Ensure permissions on /etc/gshadow are configured" "Fail" "High" "Quick" "Run: chmod 640 /etc/gshadow; chown root:shadow /etc/gshadow"
    fi
}

# Check 19: Ensure cron daemon is enabled
check_cron_enabled() {
    if systemctl is-enabled cron >/dev/null 2>&1; then
        add_result "3.5.1" "Ensure cron daemon is enabled" "Pass" "Medium" "Quick" "Run: systemctl enable cron; systemctl start cron"
    else
        add_result "3.5.1" "Ensure cron daemon is enabled" "Fail" "Medium" "Quick" "Run: systemctl enable cron; systemctl start cron"
    fi
}

# Check 20: Ensure permissions on /etc/crontab are configured
check_crontab_permissions() {
    local perms
    local owner
    local group
    perms=$(stat -c "%a" /etc/crontab 2>/dev/null)
    owner=$(stat -c "%U" /etc/crontab 2>/dev/null)
    group=$(stat -c "%G" /etc/crontab 2>/dev/null)
    if [ "$perms" = "600" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        add_result "5.1.1" "Ensure permissions on /etc/crontab are configured" "Pass" "Medium" "Quick" "Run: chmod 600 /etc/crontab; chown root:root /etc/crontab"
    else
        add_result "5.1.1" "Ensure permissions on /etc/crontab are configured" "Fail" "Medium" "Quick" "Run: chmod 600 /etc/crontab; chown root:root /etc/crontab"
    fi
}

# Check 21: Ensure permissions on /etc/cron.d are configured
check_cron_d_permissions() {
    local perms
    local owner
    local group
    perms=$(stat -c "%a" /etc/cron.d 2>/dev/null)
    owner=$(stat -c "%U" /etc/cron.d 2>/dev/null)
    group=$(stat -c "%G" /etc/cron.d 2>/dev/null)
    if [ "$perms" = "700" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        add_result "5.1.8" "Ensure permissions on /etc/cron.d are configured" "Pass" "Medium" "Quick" "Run: chmod 700 /etc/cron.d; chown root:root /etc/cron.d"
    else
        add_result "5.1.8" "Ensure permissions on /etc/cron.d are configured" "Fail" "Medium" "Quick" "Run: chmod 700 /etc/cron.d; chown root:root /etc/cron.d"
    fi
}

# Check 22: Ensure rsyslog service is enabled
check_rsyslog_enabled() {
    if systemctl is-enabled rsyslog >/dev/null 2>&1; then
        add_result "4.2.1" "Ensure rsyslog service is enabled" "Pass" "Medium" "Quick" "Run: apt install rsyslog; systemctl enable rsyslog; systemctl start rsyslog"
    else
        add_result "4.2.1" "Ensure rsyslog service is enabled" "Fail" "Medium" "Quick" "Run: apt install rsyslog; systemctl enable rsyslog; systemctl start rsyslog"
    fi
}

# Check 23: Ensure logrotate is installed
check_logrotate_installed() {
    if dpkg -s logrotate >/dev/null 2>&1; then
        add_result "4.3.1" "Ensure logrotate is installed" "Pass" "Medium" "Quick" "Run: apt install logrotate"
    else
        add_result "4.3.1" "Ensure logrotate is installed" "Fail" "Medium" "Quick" "Run: apt install logrotate"
    fi
}

# Check 24: Ensure telnet server is not installed
check_telnet_server() {
    if ! dpkg -s telnetd >/dev/null 2>&1; then
        add_result "2.2.1" "Ensure telnet server is not installed" "Pass" "High" "Quick" "Run: apt remove telnetd"
    else
        add_result "2.2.1" "Ensure telnet server is not installed" "Fail" "High" "Quick" "Run: apt remove telnetd"
    fi
}

# Check 25: Ensure FTP server is not installed
check_ftp_server() {
    if ! dpkg -s vsftpd >/dev/null 2>&1; then
        add_result "2.2.2" "Ensure FTP server is not installed" "Pass" "High" "Quick" "Run: apt remove vsftpd"
    else
        add_result "2.2.2" "Ensure FTP server is not installed" "Fail" "High" "Quick" "Run: apt remove vsftpd"
    fi
}

# Check 26: Ensure NFS server is not installed
check_nfs_server() {
    if ! dpkg -s nfs-kernel-server >/dev/null 2>&1; then
        add_result "2.2.3" "Ensure NFS server is not installed" "Pass" "Medium" "Quick" "Run: apt remove nfs-kernel-server"
    else
        add_result "2.2.3" "Ensure NFS server is not installed" "Fail" "Medium" "Quick" "Run: apt remove nfs-kernel-server"
    fi
}

# Check 27: Ensure DNS server is not installed
check_dns_server() {
    if ! dpkg -s bind9 >/dev/null 2>&1; then
        add_result "2.2.4" "Ensure DNS server is not installed" "Pass" "Medium" "Quick" "Run: apt remove bind9"
    else
        add_result "2.2.4" "Ensure DNS server is not installed" "Fail" "Medium" "Quick" "Run: apt remove bind9"
    fi
}

# Check 28: Ensure mail transfer agent is configured for local-only
check_mta_local_only() {
    if ! systemctl is-active postfix >/dev/null 2>&1 || grep -q "inet_interfaces = loopback-only" /etc/postfix/main.cf 2>/dev/null; then
        add_result "2.2.5" "Ensure mail transfer agent is configured for local-only" "Pass" "Medium" "Quick" "Edit /etc/postfix/main.cf and set 'inet_interfaces = loopback-only'. Restart postfix."
    else
        add_result "2.2.5" "Ensure mail transfer agent is configured for local-only" "Fail" "Medium" "Quick" "Edit /etc/postfix/main.cf and set 'inet_interfaces = loopback-only'. Restart postfix."
    fi
}

# Check 29: Ensure chrony is configured
check_chrony_configured() {
    if dpkg -s chrony >/dev/null 2>&1 && systemctl is-enabled chrony >/dev/null 2>&1; then
        add_result "2.2.6" "Ensure chrony is configured" "Pass" "Medium" "Quick" "Run: apt install chrony; systemctl enable chrony; systemctl start chrony"
    else
        add_result "2.2.6" "Ensure chrony is configured" "Fail" "Medium" "Quick" "Run: apt install chrony; systemctl enable chrony; systemctl start chrony"
    fi
}

# Check 30: Ensure X Window System is not installed
check_x_window_system() {
    if ! dpkg -s xserver-xorg >/dev/null 2>&1; then
        add_result "2.2.7" "Ensure X Window System is not installed" "Pass" "Medium" "Quick" "Run: apt remove xserver-xorg"
    else
        add_result "2.2.7" "Ensure X Window System is not installed" "Fail" "Medium" "Quick" "Run: apt remove xserver-xorg"
    fi
}

# Check 31: Ensure Avahi server is not installed
check_avahi_server() {
    if ! dpkg -s avahi-daemon >/dev/null 2>&1; then
        add_result "2.2.8" "Ensure Avahi server is not installed" "Pass" "Medium" "Quick" "Run: apt remove avahi-daemon"
    else
        add_result "2.2.8" "Ensure Avahi server is not installed" "Fail" "Medium" "Quick" "Run: apt remove avahi-daemon"
    fi
}

# Check 32: Ensure CUPS is not installed
check_cups() {
    if ! dpkg -s cups >/dev/null 2>&1; then
        add_result "2.2.9" "Ensure CUPS is not installed" "Pass" "Medium" "Quick" "Run: apt remove cups"
    else
        add_result "2.2.9" "Ensure CUPS is not installed" "Fail" "Medium" "Quick" "Run: apt remove cups"
    fi
}

# Check 33: Ensure DHCP server is not installed
check_dhcp_server() {
    if ! dpkg -s isc-dhcp-server >/dev/null 2>&1; then
        add_result "2.2.10" "Ensure DHCP server is not installed" "Pass" "Medium" "Quick" "Run: apt remove isc-dhcp-server"
    else
        add_result "2.2.10" "Ensure DHCP server is not installed" "Fail" "Medium" "Quick" "Run: apt remove isc-dhcp-server"
    fi
}

# Check 34: Ensure LDAP server is not installed
check_ldap_server() {
    if ! dpkg -s slapd >/dev/null 2>&1; then
        add_result "2.2.11" "Ensure LDAP server is not installed" "Pass" "Medium" "Quick" "Run: apt remove slapd"
    else
        add_result "2.2.11" "Ensure LDAP server is not installed" "Fail" "Medium" "Quick" "Run: apt remove slapd"
    fi
}

# Check 35: Ensure SNMP server is not installed
check_snmp_server() {
    if ! dpkg -s snmpd >/dev/null 2>&1; then
        add_result "2.2.12" "Ensure SNMP server is not installed" "Pass" "Medium" "Quick" "Run: apt remove snmpd"
    else
        add_result "2.2.12" "Ensure SNMP server is not installed" "Fail" "Medium" "Quick" "Run: apt remove snmpd"
    fi
}

# Check 36: Ensure Samba is not installed
check_samba() {
    if ! dpkg -s samba >/dev/null 2>&1; then
        add_result "2.2.13" "Ensure Samba is not installed" "Pass" "Medium" "Quick" "Run: apt remove samba"
    else
        add_result "2.2.13" "Ensure Samba is not installed" "Fail" "Medium" "Quick" "Run: apt remove samba"
    fi
}

# Check 37: Ensure HTTP server is not installed
check_http_server() {
    if ! dpkg -s apache2 >/dev/null 2>&1 && ! dpkg -s nginx >/dev/null 2>&1; then
        add_result "2.2.14" "Ensure HTTP server is not installed" "Pass" "Medium" "Quick" "Run: apt remove apache2 nginx"
    else
        add_result "2.2.14" "Ensure HTTP server is not installed" "Fail" "Medium" "Quick" "Run: apt remove apache2 nginx"
    fi
}

# Check 38: Ensure IMAP and POP3 server is not installed
check_imap_pop3_server() {
    if ! dpkg -s dovecot-imapd >/dev/null 2>&1 && ! dpkg -s dovecot-pop3d >/dev/null 2>&1; then
        add_result "2.2.15" "Ensure IMAP and POP3 server is not installed" "Pass" "Medium" "Quick" "Run: apt remove dovecot-imapd dovecot-pop3d"
    else
        add_result "2.2.15" "Ensure IMAP and POP3 server is not installed" "Fail" "Medium" "Quick" "Run: apt remove dovecot-imapd dovecot-pop3d"
    fi
}

# Check 39: Ensure NIS server is not installed
check_nis_server() {
    if ! dpkg -s nis >/dev/null 2>&1; then
        add_result "2.2.16" "Ensure NIS server is not installed" "Pass" "Medium" "Quick" "Run: apt remove nis"
    else
        add_result "2.2.16" "Ensure NIS server is not installed" "Fail" "Medium" "Quick" "Run: apt remove nis"
    fi
}

# Check 40: Ensure rsh server is not installed
check_rsh_server() {
    if ! dpkg -s rsh-server >/dev/null 2>&1; then
        add_result "2.2.17" "Ensure rsh samba server is not installed" "Pass" "High" "Quick" "Run: apt remove rsh-server"
    else
        add_result "2.2.17" "Ensure rsh server is not installed" "Fail" "High" "Quick" "Run: apt remove rsh-server"
    fi
}

# Check 41: Ensure bootloader password is set
check_bootloader_password() {
    if [ -f /boot/grub/grub.cfg ] && grep -q "set superusers=" /boot/grub/grub.cfg 2>/dev/null; then
        add_result "1.5.1" "Ensure bootloader password is set" "Pass" "High" "Quick" "Set a password for GRUB: grub-mkpasswd-pbkdf2"
    else
        add_result "1.5.1" "Ensure bootloader password is set" "Fail" "High" "Quick" "Set a password for GRUB: grub-mkpasswd-pbkdf2"
    fi
}

# Check 42: Ensure /etc/motd is configured
check_motd() {
    if [ -s /etc/motd ]; then
        add_result "5.7.1" "Ensure /etc/motd is configured" "Pass" "Low" "Quick" "Edit /etc/motd to include a legal banner."
    else
        add_result "5.7.1" "Ensure /etc/motd is configured" "Fail" "Low" "Quick" "Edit /etc/motd to include a legal banner."
    fi
}

# Check 43: Ensure GDM is configured properly
check_gdm() {
    if ! dpkg -s gdm3 >/dev/null 2>&1 || systemctl is-enabled gdm3 >/dev/null 2>&1; then
        add_result "5.7.2" "Ensure GDM is configured properly" "Pass" "Medium" "Quick" "Run: apt remove gdm3 or configure GDM settings."
    else
        add_result "5.7.2" "Ensure GDM is configured properly" "Fail" "Medium" "Quick" "Run: apt remove gdm3 or configure GDM settings."
    fi
}

# Check 44: Ensure AppArmor is enabled
check_apparmor() {
    if dpkg -s apparmor >/dev/null 2>&1 && systemctl is-enabled apparmor >/dev/null 2>&1; then
        add_result "1.6.1" "Ensure AppArmor is enabled" "Pass" "High" "Quick" "Run: apt install apparmor; systemctl enable apparmor"
    else
        add_result "1.6.1" "Ensure AppArmor is enabled" "Fail" "High" "Quick" "Run: apt install apparmor; systemctl enable apparmor"
    fi
}

# Check 45: Ensure separate partition exists for /home
check_home_partition() {
    if mountpoint -q /home; then
        add_result "1.1.4.1" "Ensure separate partition exists for /home" "Pass" "High" "Involved" "Configure /home as a separate partition in /etc/fstab."
    else
        add_result "1.1.4.1" "Ensure separate partition exists for /home" "Fail" "High" "Involved" "Configure /home as a separate partition in /etc/fstab."
    fi
}

# Check 46: Ensure nodev option set on /home partition
check_home_nodev() {
    if mount | grep /home | grep -q nodev; then
        add_result "1.1.4.2" "Ensure nodev option set on /home partition" "Pass" "Medium" "Quick" "Add nodev option to /home in /etc/fstab and remount."
    else
        add_result "1.1.4.2" "Ensure nodev option set on /home partition" "Fail" "Medium" "Quick" "Add nodev option to /home in /etc/fstab and remount."
    fi
}

# Check 47: Ensure nosuid option set on /home partition
check_home_nosuid() {
    if mount | grep /home | grep -q nosuid; then
        add_result "1.1.4.3" "Ensure nosuid option set on /home partition" "Pass" "Medium" "Quick" "Add nosuid option to /home in /etc/fstab and remount."
    else
        add_result "1.1.4.3" "Ensure nosuid option set on /home partition" "Fail" "Medium" "Quick" "Add nosuid option to /home in /etc/fstab and remount."
    fi
}

# Check 48: Ensure /var/log/audit is a separate partition
check_var_log_audit_partition() {
    if mountpoint -q /var/log/audit; then
        add_result "1.1.5.1" "Ensure /var/log/audit is a separate partition" "Pass" "High" "Involved" "Configure /var/log/audit as a separate partition in /etc/fstab."
    else
        add_result "1.1.5.1" "Ensure /var/log/audit is a separate partition" "Fail" "High" "Involved" "Configure /var/log/audit as a separate partition in /etc/fstab."
    fi
}

# Check 49: Ensure permissions on /etc/fstab are configured
check_fstab_permissions() {
    local perms
    local owner
    local group
    perms=$(stat -c "%a" /etc/fstab 2>/dev/null)
    owner=$(stat -c "%U" /etc/fstab 2>/dev/null)
    group=$(stat -c "%G" /etc/fstab 2>/dev/null)
    if [ "$perms" = "644" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        add_result "5.4.5" "Ensure permissions on /etc/fstab are configured" "Pass" "Medium" "Quick" "Run: chmod 644 /etc/fstab; chown root:root /etc/fstab"
    else
        add_result "5.4.5" "Ensure permissions on /etc/fstab are configured" "Fail" "Medium" "Quick" "Run: chmod 644 /etc/fstab; chown root:root /etc/fstab"
    fi
}

# Check 50: Ensure cron.hourly permissions are configured
check_cron_hourly_permissions() {
    local perms
    local owner
    local group
    perms=$(stat -c "%a" /etc/cron.hourly 2>/dev/null)
    owner=$(stat -c "%U" /etc/cron.hourly 2>/dev/null)
    group=$(stat -c "%G" /etc/cron.hourly 2>/dev/null)
    if [ "$perms" = "700" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        add_result "5.1.2" "Ensure permissions on /etc/cron.hourly are configured" "Pass" "Medium" "Quick" "Run: chmod 700 /etc/cron.hourly; chown root:root /etc/cron.hourly"
    else
        add_result "5.1.2" "Ensure permissions on /etc/cron.hourly are configured" "Fail" "Medium" "Quick" "Run: chmod 700 /etc/cron.hourly; chown root:root /etc/cron.hourly"
    fi
}

# Check 51: Ensure cron.daily permissions are configured
check_cron_daily_permissions() {
    local perms
    local owner
    local group
    perms=$(stat -c "%a" /etc/cron.daily 2>/dev/null)
    owner=$(stat -c "%U" /etc/cron.daily 2>/dev/null)
    group=$(stat -c "%G" /etc/cron.daily 2>/dev/null)
    if [ "$perms" = "700" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        add_result "5.1.3" "Ensure permissions on /etc/cron.daily are configured" "Pass" "Medium" "Quick" "Run: chmod 700 /etc/cron.daily; chown root:root /etc/cron.daily"
    else
        add_result "5.1.3" "Ensure permissions on /etc/cron.daily are configured" "Fail" "Medium" "Quick" "Run: chmod 700 /etc/cron.daily; chown root:root /etc/cron.daily"
    fi
}

# Check 52: Ensure cron.weekly permissions are configured
check_cron_weekly_permissions() {
    local perms
    local owner
    local group
    perms=$(stat -c "%a" /etc/cron.weekly 2>/dev/null)
    owner=$(stat -c "%U" /etc/cron.weekly 2>/dev/null)
    group=$(stat -c "%G" /etc/cron.weekly 2>/dev/null)
    if [ "$perms" = "700" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        add_result "5.6.4" "Ensure permissions on /etc/cron.weekly are configured" "Pass" "Medium" "Quick" "Run: chmod 700 /etc/cron.weekly; chown root:root /etc/cron.weekly"
    else
        add_result "5.6.4" "Ensure permissions on /etc/cron.weekly are configured" "Fail" "Medium" "Quick" "Run: chmod 700 /etc/cron.weekly; chown root:root /etc/cron.weekly"
    fi
}

# Check 53: Ensure cron.monthly permissions are configured
check_cron_monthly_permissions() {
    local perms
    local owner
    local group
    perms=$(stat -c "%a" /etc/cron.monthly 2>/dev/null)
    owner=$(stat -c "%U" /etc/cron.monthly 2>/dev/null)
    group=$(stat -c "%G" /etc/cron.monthly 2>/dev/null)
    if [ "$perms" = "700" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        add_result "5.1.5" "Ensure permissions on /etc/cron.monthly are configured" "Pass" "Medium" "Quick" "Run: chmod 700 /etc/cron.monthly; chown root:root /etc/cron.monthly"
    else
        add_result "5.1.5" "Ensure permissions on /etc/cron.monthly are configured" "Fail" "Medium" "Quick" "Run: chmod 700 /etc/cron.monthly; chown root:root /etc/cron.monthly"
    fi
}

# Check 54: Ensure at is restricted
check_at_restrictions() {
    if [ -f /etc/at.allow ] || [ -f /etc/at.deny ]; then
        add_result "5.1.6" "Ensure at is restricted" "Pass" "Medium" "Quick" "Configure /etc/at.allow or /etc/at.deny to restrict at access."
    else
        add_result "5.1.6" "Ensure at is restricted" "Fail" "Medium" "Quick" "Configure /etc/at.allow or /etc/at.deny to restrict at access."
 
   fi
}

# Check 55: Ensure SSH IgnoreRhosts is enabled
check_ssh_ignorerhosts() {
    if grep -q "^IgnoreRhosts yes" /etc/ssh/sshd_config 2>/dev/null; then
        add_result "5.2.7" "Ensure SSH IgnoreRhosts is enabled" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'IgnoreRhosts yes'. Restart sshd."
    else
        add_result "5.2.7" "Ensure SSH IgnoreRhosts is enabled" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'IgnoreRhosts yes'. Restart sshd."
    fi
}

# Check 56: Ensure SSH HostbasedAuthentication is disabled
check_ssh_hostbasedauth() {
    if grep -q "^HostbasedAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
        add_result "5.2.8" "Ensure SSH HostbasedAuthentication is disabled" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'HostbasedAuthentication no'. Restart sshd."
    else
        add_result "5.2.8" "Ensure SSH HostbasedAuthentication is disabled" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'HostbasedAuthentication no'. Restart sshd."
    fi
}

# Check 57: Ensure SSH AllowTcpForwarding is disabled
check_ssh_tcpforwarding() {
    if grep -q "^AllowTcpForwarding no" /etc/ssh/sshd_config 2>/dev/null; then
        add_result "5.2.9" "Ensure SSH AllowTcpForwarding is disabled" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'AllowTcpForwarding no'. Restart sshd."
    else
        add_result "5.2.9" "Ensure SSH AllowTcpForwarding is disabled" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'AllowTcpForwarding no'. Restart sshd."
    fi
}

# Check 58: Ensure SSH MaxStartups is configured
check_ssh_maxstartups() {
    if grep -q "^MaxStartups 10:30:60" /etc/ssh/sshd_config 2>/dev/null; then
        add_result "5.2.10" "Ensure SSH MaxStartups is configured" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'MaxStartups 10:30:60'. Restart sshd."
    else
        add_result "5.2.10" "Ensure SSH MaxStartups is configured" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'MaxStartups 10:30:60'. Restart sshd."
    fi
}

# Check 59: Ensure SSH ClientAliveInterval is configured
check_ssh_clientaliveinterval() {
    if grep -q "^ClientAliveInterval 300" /etc/ssh/sshd_config 2>/dev/null; then
        add_result "5.2.11" "Ensure SSH ClientAliveInterval is configured" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'ClientAliveInterval 300'. Restart sshd."
    else
        add_result "5.2.11" "Ensure SSH ClientAliveInterval is configured" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'ClientAliveInterval 300'. Restart sshd."
    fi
}

# Check 60: Ensure SSH ClientAliveCountMax is configured
check_ssh_clientalivecountmax() {
    if grep -q "^ClientAliveCountMax 3" /etc/ssh/sshd_config 2>/dev/null; then
        add_result "5.2.12" "Ensure SSH ClientAliveCountMax is configured" "Pass" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'ClientAliveCountMax 3'. Restart sshd."
    else
        add_result "5.2.12" "Ensure SSH ClientAliveCountMax is configured" "Fail" "Medium" "Quick" "Edit /etc/ssh/sshd_config and set 'ClientAliveCountMax 3'. Restart sshd."
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
rm "$TABLE_ROWS_FILE"
