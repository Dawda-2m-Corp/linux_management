#!/bin/bash

# ============================================================================
# Security Hardening Script — NSA/DISA STIG Enhanced
# Based on:
#   - NSA Guide to the Secure Configuration of Red Hat Enterprise Linux
#   - DISA STIG for Ubuntu 22.04 LTS (April 2024)
#   - NIST SP 800-53 / CIS Benchmarks
# ============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Log file
SECURITY_LOG="/var/log/security_hardening.log"

# Timestamped backup directory (NSA: always backup before modifying)
BACKUP_DIR="/root/security_backups_$(date +%Y%m%d_%H%M%S)"

# ============================================================================
# UTILITIES
# ============================================================================

log_message() {
    local message="$1"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" | sudo tee -a "$SECURITY_LOG" >/dev/null 2>&1 \
        || echo "[$timestamp] $message"
    echo -e "$message"
}

# Backup a file before modifying it (NSA best practice)
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        mkdir -p "$BACKUP_DIR/$(dirname "$file")"
        cp -p "$file" "$BACKUP_DIR/$file"
        log_message "${CYAN}Backed up: $file → $BACKUP_DIR/$file${NC}"
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        exit 1
    fi
}

# Detect package manager
detect_pkg_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    else
        echo "unknown"
    fi
}

# ============================================================================
# USAGE
# ============================================================================

show_usage() {
    echo -e "${BLUE}Security Hardening Script — NSA/DISA STIG Enhanced${NC}"
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  audit              Perform security audit"
    echo "  harden             Apply kernel/network hardening"
    echo "  firewall           Configure firewall"
    echo "  ssh-harden         Harden SSH (STIG-aligned)"
    echo "  password-policy    Set password policy"
    echo "  fail2ban           Install and configure fail2ban"
    echo "  updates            Configure automatic security updates"
    echo "  permissions        Fix file/directory permissions"
    echo "  auditd             Configure auditd (NSA/STIG logging)"    # NEW
    echo "  mac                Enable Mandatory Access Control"         # NEW
    echo "  aide               Set up file integrity monitoring"        # NEW
    echo "  grub-harden        Secure bootloader (STIG)"               # NEW
    echo "  disable-services   Disable unnecessary services (STIG)"    # NEW
    echo "  coredumps          Restrict core dumps (STIG)"             # NEW
    echo "  all                Run all hardening steps"
    echo ""
}

# ============================================================================
# SECURITY AUDIT (expanded)
# ============================================================================

security_audit() {
    log_message "${BLUE}=== Security Audit Started ===${NC}"

    log_message "${BLUE}[1] Users with UID 0 (should only be root):${NC}"
    awk -F: '$3 == 0 {print $1}' /etc/passwd

    log_message "${BLUE}[2] Accounts with empty passwords:${NC}"
    awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null \
        || echo "Cannot access /etc/shadow (run as root)"

    log_message "${BLUE}[3] World-writable files in critical directories:${NC}"
    find /etc /usr/bin /usr/sbin /bin /sbin -type f -perm -002 2>/dev/null | head -10

    log_message "${BLUE}[4] SUID/SGID binaries:${NC}"
    find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null | head -20

    log_message "${BLUE}[5] Listening network services:${NC}"
    if command -v ss >/dev/null 2>&1; then ss -tuln; else netstat -tuln; fi

    log_message "${BLUE}[6] Recent login activity:${NC}"
    last -10

    log_message "${BLUE}[7] Failed login attempts:${NC}"
    grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5 \
        || journalctl _COMM=sshd 2>/dev/null | grep "Failed" | tail -5 \
        || echo "No auth log or no failures found"

    # ── NSA ADDITIONS ──────────────────────────────────────────────────────

    log_message "${BLUE}[8] Unowned files (orphaned — NSA check):${NC}"
    # NSA: files with no valid owner/group can indicate tampering or leftover installs
    find / -nouser -o -nogroup 2>/dev/null | grep -v "^/proc" | head -10

    log_message "${BLUE}[9] .rhosts / .netrc / .shosts files (NSA: must not exist):${NC}"
    find /home /root -name ".rhosts" -o -name ".netrc" -o -name ".shosts" 2>/dev/null

    log_message "${BLUE}[10] Writable PATH directories for root:${NC}"
    # NSA: root's PATH must not contain world/group-writable directories
    for dir in $(echo "$PATH" | tr ':' ' '); do
        [[ -d "$dir" ]] && ls -ld "$dir"
    done

    log_message "${BLUE}[11] Cron jobs (all users):${NC}"
    # NSA: review scheduled tasks for unauthorized entries
    for user in $(cut -f1 -d: /etc/passwd); do
        crontab -u "$user" -l 2>/dev/null && echo "  ↑ user: $user"
    done
    ls -la /etc/cron* /var/spool/cron/ 2>/dev/null || true

    log_message "${BLUE}[12] auditd status (NSA/STIG: must be running):${NC}"
    systemctl is-active auditd 2>/dev/null || echo "auditd NOT running — run 'auditd' command"

    log_message "${BLUE}[13] MAC (AppArmor/SELinux) status (NSA/STIG: must be enforcing):${NC}"
    if command -v aa-status >/dev/null 2>&1; then
        aa-status --enabled 2>/dev/null && echo "AppArmor: active" || echo "AppArmor: inactive"
    elif command -v getenforce >/dev/null 2>&1; then
        getenforce
    else
        echo "No MAC framework detected — run 'mac' command"
    fi

    log_message "${BLUE}[14] Secure Boot status (NSA guidance):${NC}"
    if command -v mokutil >/dev/null 2>&1; then
        mokutil --sb-state 2>/dev/null || echo "mokutil unavailable"
    else
        echo "mokutil not installed — install to verify Secure Boot"
    fi

    log_message "${GREEN}Security audit completed${NC}"
}

# ============================================================================
# KERNEL / NETWORK HARDENING (expanded)
# ============================================================================

basic_hardening() {
    check_root
    log_message "${BLUE}=== Kernel & Network Hardening ===${NC}"

    # ── Disable rare/unused network protocols ─────────────────────────────
    # NSA: reduce attack surface by preventing loading of unneeded kernel modules
    backup_file /etc/modprobe.d/blacklist-rare-network.conf
    cat >> /etc/modprobe.d/blacklist-rare-network.conf << 'EOF'
# NSA: Disable uncommon/unused network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
# NSA: Disable Bluetooth if not needed
install bluetooth /bin/true
install btusb /bin/true
# STIG: Disable USB storage (remove if USB drives are operationally required)
# install usb-storage /bin/true
EOF

    # ── Kernel sysctl parameters ─────────────────────────────────────────
    backup_file /etc/sysctl.d/99-security.conf
    cat > /etc/sysctl.d/99-security.conf << 'EOF'
# ── Network: IP Spoofing / Redirect Protection ────────────────────────────
# NSA: Enable reverse-path filtering to block spoofed source addresses
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

# NSA: Do not send ICMP redirects (we are not a router)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# NSA: Do not accept source-routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# NSA: Do not accept ICMP redirects (prevents routing table poisoning)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# NSA: Log suspicious ("Martian") packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# NSA: Ignore ICMP broadcast requests (Smurf attack mitigation)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# NSA: Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# NSA: Enable SYN cookies to resist SYN flood attacks
net.ipv4.tcp_syncookies = 1

# STIG: Disable IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# NSA: Disable IP forwarding (unless this host is a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# ── Kernel: Memory & Exploit Mitigations ─────────────────────────────────
# NSA/STIG: Restrict dmesg to root only (prevents info leaks)
kernel.dmesg_restrict = 1

# NSA: Restrict access to kernel pointers in /proc (prevents ASLR bypass)
kernel.kptr_restrict = 2

# NSA/STIG: Disable magic SysRq key (prevent console-based attacks)
kernel.sysrq = 0

# NSA: Restrict ptrace to parent processes only (limits process inspection)
kernel.yama.ptrace_scope = 1

# NSA: Disable core dumps for setuid binaries (prevent credential leaks)
fs.suid_dumpable = 0

# NSA: Randomise virtual address space (ASLR — should be 2 = full)
kernel.randomize_va_space = 2

# STIG: Restrict unprivileged BPF (eBPF attack surface reduction)
kernel.unprivileged_bpf_disabled = 1

# STIG: Harden BPF JIT compiler
net.core.bpf_jit_harden = 2

# STIG: Restrict user namespaces (reduce container escape surface)
kernel.unprivileged_userns_clone = 0

# NSA: Limit PID reuse speed (complicates PID-guessing attacks)
kernel.pid_max = 65536

# ── File system hardening ─────────────────────────────────────────────────
# NSA: Protect hardlinks — only owner/root can follow
fs.protected_hardlinks = 1

# NSA: Protect symlinks — only follow if owner matches
fs.protected_symlinks = 1
EOF

    sysctl -p /etc/sysctl.d/99-security.conf

    # ── Secure default umask ──────────────────────────────────────────────
    # NSA: umask 027 means new files are not readable by "other"
    backup_file /etc/profile
    grep -q "umask 027" /etc/profile || echo "umask 027" >> /etc/profile
    backup_file /etc/login.defs
    sed -i 's/^UMASK.*/UMASK\t\t027/' /etc/login.defs

    log_message "${GREEN}Kernel & network hardening completed${NC}"
}

# ============================================================================
# FIREWALL
# ============================================================================

configure_firewall() {
    check_root
    log_message "${BLUE}=== Configuring Firewall ===${NC}"

    if command -v ufw >/dev/null 2>&1; then
        log_message "${BLUE}Configuring UFW...${NC}"
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        # NSA: explicitly deny forwarding by default
        ufw default deny routed
        ufw allow ssh
        # NSA: enable logging for denied packets
        ufw logging on
        ufw --force enable
        ufw status verbose

    elif command -v firewall-cmd >/dev/null 2>&1; then
        log_message "${BLUE}Configuring firewalld...${NC}"
        systemctl enable --now firewalld
        firewall-cmd --set-default-zone=drop   # NSA: use DROP (not reject) as default
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --reload
        firewall-cmd --list-all

    elif command -v iptables >/dev/null 2>&1; then
        log_message "${BLUE}Configuring iptables...${NC}"
        iptables -F; iptables -X
        iptables -t nat -F; iptables -t nat -X
        iptables -t mangle -F; iptables -t mangle -X

        # NSA: default DROP policy on INPUT and FORWARD
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT ACCEPT

        iptables -A INPUT -i lo -j ACCEPT
        iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT

        # NSA: log dropped packets before final drop rule
        iptables -A INPUT -m limit --limit 5/min -j LOG \
            --log-prefix "iptables-dropped: " --log-level 4

        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null \
                || iptables-save > /etc/iptables.rules 2>/dev/null \
                || echo "Manual iptables-save required"
        fi
    else
        log_message "${YELLOW}No supported firewall found${NC}"
        return 1
    fi

    log_message "${GREEN}Firewall configuration completed${NC}"
}

# ============================================================================
# SSH HARDENING (STIG-aligned)
# ============================================================================

harden_ssh() {
    check_root
    log_message "${BLUE}=== Hardening SSH (STIG-aligned) ===${NC}"

    local ssh_config="/etc/ssh/sshd_config"
    [[ ! -f "$ssh_config" ]] && { log_message "${YELLOW}sshd_config not found${NC}"; return 1; }

    backup_file "$ssh_config"

    # Write a clean STIG-compliant sshd_config drop-in
    # Using /etc/ssh/sshd_config.d/ if supported (Ubuntu 22.04+), else append
    local dropin_dir="/etc/ssh/sshd_config.d"
    if [[ -d "$dropin_dir" ]]; then
        local dropin="${dropin_dir}/99-stig-hardening.conf"
        log_message "${BLUE}Writing STIG SSH config to $dropin${NC}"
        cat > "$dropin" << 'EOF'
# NSA/DISA STIG SSH Hardening
# -- Protocol & Authentication --
Protocol 2
PermitRootLogin no                  # STIG: root must not log in directly
PasswordAuthentication no           # NSA: key-based auth only
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# -- Access Control --
# Adjust AllowUsers/AllowGroups to your environment before enabling:
# AllowGroups sshusers
DenyUsers root

# -- Session Limits --
MaxAuthTries 3                      # STIG: limit brute-force attempts
MaxSessions 4                       # STIG: limit concurrent sessions
LoginGraceTime 60                   # STIG: 60-second authentication window
ClientAliveInterval 300             # STIG: disconnect idle sessions after 5 min
ClientAliveCountMax 0               # STIG: no keepalives = disconnect immediately

# -- Crypto (NSA/STIG: only approved algorithms) --
# Ciphers approved by NSA Suite B / CNSA
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519

# -- Forwarding / Tunneling (NSA: disable all unless operationally required) --
X11Forwarding no
AllowTcpForwarding no               # NSA: prevent SSH tunnelling
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no

# -- Miscellaneous --
Banner /etc/issue.net               # STIG: display legal warning before login
PrintLastLog yes                    # NSA: show last login time
UsePrivilegeSeparation sandbox      # mitigate privilege escalation
StrictModes yes
Compression no                      # CVE-2008-5161 mitigation
MaxStartups 10:30:60                # mitigate connection flooding
TCPKeepAlive no                     # rely on ClientAlive instead
LogLevel VERBOSE                    # STIG: log key fingerprints
EOF
    else
        # Fallback: append to main sshd_config
        grep -v "^#" "$ssh_config" | grep -v "^$" > /tmp/sshd_clean
        mv /tmp/sshd_clean "$ssh_config"
        cat >> "$ssh_config" << 'EOF'
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 0
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group14-sha256
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
Banner /etc/issue.net
PrintLastLog yes
Compression no
LogLevel VERBOSE
EOF
    fi

    # Legal banner (STIG-required)
    cat > /etc/issue.net << 'EOF'
***************************************************************************
                            NOTICE TO USERS
***************************************************************************
This system is for authorized use only. By using this system, you
consent to monitoring and recording of all activity. Unauthorized access
or use is prohibited and may be subject to criminal prosecution.
***************************************************************************
EOF
    # Also set /etc/issue (shown at local console)
    cp /etc/issue.net /etc/issue

    if sshd -t; then
        log_message "${GREEN}SSH config test passed — reloading sshd${NC}"
        systemctl reload sshd || service ssh reload
    else
        log_message "${RED}SSH config test FAILED — reverting${NC}"
        cp "$BACKUP_DIR/etc/ssh/sshd_config" "$ssh_config"
        return 1
    fi

    log_message "${GREEN}SSH hardening completed${NC}"
}

# ============================================================================
# PASSWORD POLICY
# ============================================================================

set_password_policy() {
    check_root
    log_message "${BLUE}=== Setting Password Policy (STIG) ===${NC}"

    local pkg_mgr
    pkg_mgr=$(detect_pkg_manager)
    if [[ "$pkg_mgr" == "apt" ]]; then
        apt-get update -qq && apt-get install -y libpam-pwquality
    elif [[ "$pkg_mgr" == "yum" || "$pkg_mgr" == "dnf" ]]; then
        "$pkg_mgr" install -y libpwquality
    fi

    if [[ -f /etc/security/pwquality.conf ]]; then
        backup_file /etc/security/pwquality.conf
        cat >> /etc/security/pwquality.conf << 'EOF'

# STIG/NSA password quality requirements
minlen = 15          # STIG: minimum 15 characters
dcredit = -1         # at least 1 digit
ucredit = -1         # at least 1 uppercase
lcredit = -1         # at least 1 lowercase
ocredit = -1         # at least 1 special character
minclass = 4         # must use all 4 character classes
maxrepeat = 3        # no more than 3 consecutive identical characters
maxsequence = 3      # no sequential chars (e.g. abc, 123)
gecoscheck = 1       # reject passwords matching GECOS/username fields
dictcheck = 1        # reject dictionary words
usercheck = 1        # reject username substrings
enforcing = 1
EOF
    fi

    # Password aging (STIG requirements)
    backup_file /etc/login.defs
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t60/'  /etc/login.defs  # STIG: 60 days max
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/'   /etc/login.defs  # STIG: 1 day min
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t7/'   /etc/login.defs

    # NSA: lock accounts after failed attempts (pam_faillock / pam_tally2)
    local pam_common_auth="/etc/pam.d/common-auth"
    if [[ -f "$pam_common_auth" ]]; then
        backup_file "$pam_common_auth"
        # pam_faillock (modern, replaces pam_tally2 on Ubuntu 22.04+)
        if ! grep -q "pam_faillock" "$pam_common_auth"; then
            sed -i '/^auth.*pam_unix/i auth    required    pam_faillock.so preauth silent deny=5 unlock_time=900' \
                "$pam_common_auth"
            sed -i '/^auth.*pam_unix/a auth    [default=die] pam_faillock.so authfail deny=5 unlock_time=900' \
                "$pam_common_auth"
        fi
    fi

    log_message "${GREEN}Password policy configuration completed${NC}"
}

# ============================================================================
# FAIL2BAN
# ============================================================================

setup_fail2ban() {
    check_root
    log_message "${BLUE}=== Setting up Fail2ban ===${NC}"

    local pkg_mgr
    pkg_mgr=$(detect_pkg_manager)
    case "$pkg_mgr" in
        apt) apt-get update -qq && apt-get install -y fail2ban ;;
        yum|dnf) "$pkg_mgr" install -y fail2ban ;;
        *) log_message "${YELLOW}Cannot auto-install fail2ban — install manually${NC}"; return 1 ;;
    esac

    backup_file /etc/fail2ban/jail.local

    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# NSA: ban for 24 hours after repeated failures
bantime  = 86400
findtime = 600
maxretry = 3
backend  = systemd
destemail = root@localhost
sender    = fail2ban@localhost
protocol  = tcp
chain     = INPUT

[sshd]
enabled  = true
port     = ssh
filter   = sshd
maxretry = 3
bantime  = 86400

[sshd-ddos]
# NSA: also catch rapid connection attempts (DDoS pattern)
enabled  = true
port     = ssh
filter   = sshd-ddos
maxretry = 6
findtime = 30
bantime  = 86400
EOF

    systemctl enable --now fail2ban
    log_message "${GREEN}Fail2ban setup completed${NC}"
}

# ============================================================================
# AUTOMATIC UPDATES
# ============================================================================

configure_updates() {
    check_root
    log_message "${BLUE}=== Configuring Automatic Security Updates ===${NC}"

    local pkg_mgr
    pkg_mgr=$(detect_pkg_manager)

    if [[ "$pkg_mgr" == "apt" ]]; then
        apt-get update -qq && apt-get install -y unattended-upgrades apt-listchanges

        backup_file /etc/apt/apt.conf.d/50unattended-upgrades
        cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
// NSA: apply security updates automatically
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
// NSA: do NOT auto-reboot during production hours; set a maintenance window instead
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailReport "on-change";
EOF

        cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    elif [[ "$pkg_mgr" == "yum" ]]; then
        yum install -y yum-cron
        sed -i 's/apply_updates = no/apply_updates = yes/' /etc/yum/yum-cron.conf
        sed -i 's/update_cmd = default/update_cmd = security/' /etc/yum/yum-cron.conf
        systemctl enable --now yum-cron

    elif [[ "$pkg_mgr" == "dnf" ]]; then
        dnf install -y dnf-automatic
        sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf
        sed -i 's/upgrade_type = default/upgrade_type = security/' /etc/dnf/automatic.conf
        systemctl enable --now dnf-automatic-install.timer
    fi

    log_message "${GREEN}Automatic updates configured${NC}"
}

# ============================================================================
# FILE PERMISSIONS
# ============================================================================

fix_permissions() {
    check_root
    log_message "${BLUE}=== Fixing File Permissions (NSA/STIG) ===${NC}"

    # STIG: critical file permissions
    chmod 000 /etc/shadow   2>/dev/null || chmod 400 /etc/shadow   2>/dev/null || true
    chmod 644 /etc/passwd
    chmod 644 /etc/group
    chmod 000 /etc/gshadow  2>/dev/null || chmod 400 /etc/gshadow  2>/dev/null || true
    chmod 600 /boot/grub*/grub.cfg 2>/dev/null || true  # NSA: protect bootloader config

    # SSH host key permissions
    if [[ -d /etc/ssh ]]; then
        chmod 755 /etc/ssh
        chmod 600 /etc/ssh/ssh_host_*_key   2>/dev/null || true
        chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true
        chmod 600 /etc/ssh/sshd_config
        [[ -d /etc/ssh/sshd_config.d ]] && chmod 700 /etc/ssh/sshd_config.d
    fi

    # Home directories
    for home in /home/*; do
        [[ -d "$home" ]] && chmod 750 "$home" \
            && chown "$(basename "$home"):$(basename "$home")" "$home" 2>/dev/null || true
    done

    # NSA: remove world-write from system dirs
    find /usr /etc -type d -perm -002 -exec chmod o-w {} \; 2>/dev/null || true

    # NSA: find and report (not auto-remove) SUID/SGID in unexpected locations
    log_message "${YELLOW}SUID/SGID binaries outside standard paths — review these:${NC}"
    find / -path /proc -prune -o -path /sys -prune -o \
        -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null \
        | grep -Ev "^(/usr/bin|/usr/sbin|/bin|/sbin)" || true

    # NSA: remove .rhosts, .netrc, .shosts — these bypass normal auth
    find /home /root -name ".rhosts" -o -name ".netrc" -o -name ".shosts" \
        2>/dev/null -exec rm -v {} \;

    log_message "${GREEN}Permission fixes completed${NC}"
}

# ============================================================================
# NEW: AUDITD — NSA/STIG AUDIT LOGGING
# ============================================================================

configure_auditd() {
    check_root
    log_message "${BLUE}=== Configuring auditd (NSA/STIG) ===${NC}"

    local pkg_mgr
    pkg_mgr=$(detect_pkg_manager)
    case "$pkg_mgr" in
        apt) apt-get install -y auditd audispd-plugins ;;
        yum|dnf) "$pkg_mgr" install -y audit audit-libs ;;
    esac

    backup_file /etc/audit/auditd.conf
    cat > /etc/audit/auditd.conf << 'EOF'
# NSA/STIG auditd configuration
log_file = /var/log/audit/audit.log
log_format = ENRICHED
log_group = root
priority_boost = 4
flush = INCREMENTAL_ASYNC
freq = 50
# STIG: retain at least 6 MB per log, keep 5 logs
max_log_file = 32
max_log_file_action = ROTATE
num_logs = 5
# STIG: halt system if disk space for audit logs runs out (no silent log loss)
space_left = 75
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = HALT
disk_full_action = HALT
disk_error_action = HALT
EOF

    # NSA/STIG audit rules
    backup_file /etc/audit/rules.d/99-stig.rules
    cat > /etc/audit/rules.d/99-stig.rules << 'EOF'
# ── NSA/DISA STIG Audit Rules ──────────────────────────────────────────────

# Delete all existing rules
-D

# Buffer size (increase if losing events under heavy load)
-b 8192

# Failure mode: 1=log, 2=panic (STIG recommends 2 for high-security systems)
-f 1

# ── Identity / authentication events ──────────────────────────────────────
-w /etc/passwd     -p wa -k identity
-w /etc/shadow     -p wa -k identity
-w /etc/group      -p wa -k identity
-w /etc/gshadow    -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# ── Privileged command use ─────────────────────────────────────────────────
-w /usr/bin/sudo   -p x  -k privileged
-w /usr/bin/su     -p x  -k privileged
-w /bin/su         -p x  -k privileged
-a always,exit -F path=/usr/bin/newgrp  -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh    -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# ── Login / session events ─────────────────────────────────────────────────
-w /var/log/faillog  -p wa -k logins
-w /var/log/lastlog  -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock -p wa -k logins

# ── Discretionary access control (DAC) changes ────────────────────────────
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat        -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# ── Unauthorised file access attempts ─────────────────────────────────────
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat \
    -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat \
    -F exit=-EPERM  -F auid>=1000 -F auid!=4294967295 -k access

# ── Filesystem mounts (NSA: audit media exportation) ──────────────────────
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# ── File deletions ────────────────────────────────────────────────────────
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat \
    -F auid>=1000 -F auid!=4294967295 -k delete

# ── Kernel module loading/unloading (NSA: detect rootkit installation) ────
-w /sbin/insmod    -p x -k modules
-w /sbin/rmmod     -p x -k modules
-w /sbin/modprobe  -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module -k modules

# ── Sudoers configuration ─────────────────────────────────────────────────
-w /etc/sudoers    -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# ── System calls: execution ───────────────────────────────────────────────
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k exec

# ── Network configuration changes ─────────────────────────────────────────
-a always,exit -F arch=b64 -S sethostname,setdomainname -k network_changes
-w /etc/hosts      -p wa -k network_changes
-w /etc/network    -p wa -k network_changes
-w /etc/sysconfig/network -p wa -k network_changes

# ── Time changes (NSA: audit clock manipulation) ──────────────────────────
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change
-w /etc/localtime  -p wa -k time_change

# ── Mandatory access control policy changes ───────────────────────────────
-w /etc/apparmor/   -p wa -k MAC_policy
-w /etc/apparmor.d/ -p wa -k MAC_policy
-w /etc/selinux/    -p wa -k MAC_policy

# ── Make rules immutable (requires reboot to change — use carefully) ───────
# Uncomment on high-security systems: attackers cannot then flush audit rules
# -e 2
EOF

    # NSA: enable audit=1 at kernel boot so processes started before auditd are audited
    if [[ -f /etc/default/grub ]]; then
        backup_file /etc/default/grub
        if ! grep -q "audit=1" /etc/default/grub; then
            sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 audit=1 audit_backlog_limit=8192"/' \
                /etc/default/grub
            update-grub 2>/dev/null || grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || true
        fi
    fi

    systemctl enable --now auditd
    augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/99-stig.rules
    log_message "${GREEN}auditd configuration completed${NC}"
}

# ============================================================================
# NEW: MANDATORY ACCESS CONTROL (AppArmor / SELinux)
# ============================================================================

configure_mac() {
    check_root
    log_message "${BLUE}=== Configuring Mandatory Access Control (NSA) ===${NC}"

    # NSA originated SELinux; both SELinux and AppArmor are NSA/STIG endorsed
    if command -v aa-status >/dev/null 2>&1; then
        log_message "${BLUE}AppArmor detected — enforcing all profiles${NC}"
        local pkg_mgr
        pkg_mgr=$(detect_pkg_manager)
        [[ "$pkg_mgr" == "apt" ]] && apt-get install -y apparmor apparmor-utils apparmor-profiles

        systemctl enable apparmor
        systemctl start apparmor

        # Enforce all available profiles (not just complain mode)
        aa-enforce /etc/apparmor.d/* 2>/dev/null \
            || log_message "${YELLOW}Some AppArmor profiles could not be enforced — review manually${NC}"

        aa-status
        log_message "${GREEN}AppArmor set to enforcing${NC}"

    elif command -v getenforce >/dev/null 2>&1; then
        log_message "${BLUE}SELinux detected — setting to enforcing${NC}"
        setenforce 1

        backup_file /etc/selinux/config
        sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
        sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=targeted/' /etc/selinux/config

        log_message "${GREEN}SELinux set to enforcing (targeted policy)${NC}"
        log_message "${YELLOW}A relabel + reboot may be required: 'touch /.autorelabel && reboot'${NC}"

    else
        log_message "${YELLOW}No MAC framework found — installing AppArmor${NC}"
        local pkg_mgr
        pkg_mgr=$(detect_pkg_manager)
        if [[ "$pkg_mgr" == "apt" ]]; then
            apt-get install -y apparmor apparmor-utils apparmor-profiles
            systemctl enable --now apparmor
            aa-enforce /etc/apparmor.d/* 2>/dev/null || true
            log_message "${GREEN}AppArmor installed and enforcing${NC}"
        else
            log_message "${YELLOW}Install SELinux or AppArmor manually for your distribution${NC}"
        fi
    fi
}

# ============================================================================
# NEW: FILE INTEGRITY MONITORING (AIDE)
# ============================================================================

setup_aide() {
    check_root
    log_message "${BLUE}=== Setting up AIDE File Integrity Monitoring (NSA) ===${NC}"
    # NSA: verify integrity of installed software; detect rootkits/tampering

    local pkg_mgr
    pkg_mgr=$(detect_pkg_manager)
    case "$pkg_mgr" in
        apt)  apt-get install -y aide aide-common ;;
        yum|dnf) "$pkg_mgr" install -y aide ;;
        *) log_message "${YELLOW}Cannot auto-install AIDE${NC}"; return 1 ;;
    esac

    # Initialise the AIDE database (this takes a few minutes)
    log_message "${BLUE}Initialising AIDE database (this may take several minutes)...${NC}"
    if command -v aideinit >/dev/null 2>&1; then
        aideinit -y -f
    else
        aide --init
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null \
            || mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null || true
    fi

    # Schedule daily AIDE checks via cron (NSA: regular integrity checks)
    cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
# NSA: Daily file integrity check
/usr/bin/aide --check 2>&1 | mail -s "AIDE Integrity Report: $(hostname)" root
EOF
    chmod 700 /etc/cron.daily/aide-check

    log_message "${GREEN}AIDE setup completed — daily checks scheduled${NC}"
    log_message "${YELLOW}Run 'aide --check' manually to verify integrity${NC}"
}

# ============================================================================
# NEW: GRUB BOOTLOADER HARDENING (STIG)
# ============================================================================

harden_grub() {
    check_root
    log_message "${BLUE}=== Hardening GRUB Bootloader (STIG) ===${NC}"

    if [[ ! -f /etc/default/grub ]]; then
        log_message "${YELLOW}GRUB config not found — skipping${NC}"
        return 1
    fi

    backup_file /etc/default/grub

    # STIG: add kernel boot hardening parameters
    local current_cmdline
    current_cmdline=$(grep "^GRUB_CMDLINE_LINUX=" /etc/default/grub | cut -d'"' -f2)

    local additions=""
    # STIG: disable vsyscall (kernel info leak vector)
    [[ "$current_cmdline" != *"vsyscall=none"* ]]       && additions+=" vsyscall=none"
    # NSA: enable kernel page table isolation (Meltdown mitigation)
    [[ "$current_cmdline" != *"pti=on"* ]]              && additions+=" pti=on"
    # NSA: SLAB/SLUB hardening — zero memory on free
    [[ "$current_cmdline" != *"slab_nomerge"* ]]        && additions+=" slab_nomerge"
    [[ "$current_cmdline" != *"init_on_alloc=1"* ]]     && additions+=" init_on_alloc=1"
    [[ "$current_cmdline" != *"init_on_free=1"* ]]      && additions+=" init_on_free=1"
    # NSA: randomize page allocator freelist (hardens heap spray attacks)
    [[ "$current_cmdline" != *"page_alloc.shuffle=1"* ]]&& additions+=" page_alloc.shuffle=1"
    # STIG: disable kernel lockdown bypass via /dev/mem
    [[ "$current_cmdline" != *"lockdown=confidentiality"* ]] && additions+=" lockdown=confidentiality"
    # Audit at boot (covered also in auditd section)
    [[ "$current_cmdline" != *"audit=1"* ]]             && additions+=" audit=1 audit_backlog_limit=8192"

    if [[ -n "$additions" ]]; then
        sed -i "s|^GRUB_CMDLINE_LINUX=\"\(.*\)\"|GRUB_CMDLINE_LINUX=\"\1$additions\"|" /etc/default/grub
        log_message "${BLUE}Added kernel parameters:$additions${NC}"
    fi

    # STIG: restrict GRUB config permissions
    update-grub 2>/dev/null || grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || true
    chmod 600 /boot/grub*/grub.cfg 2>/dev/null || true

    log_message "${GREEN}GRUB hardening completed — reboot required${NC}"
    log_message "${YELLOW}IMPORTANT: Set a GRUB password in BIOS/UEFI for full boot security${NC}"
}

# ============================================================================
# NEW: DISABLE UNNECESSARY SERVICES (NSA/STIG)
# ============================================================================

disable_unnecessary_services() {
    check_root
    log_message "${BLUE}=== Disabling Unnecessary Services (NSA/STIG) ===${NC}"

    # NSA: disable services not required for system function
    # Adjust this list to match your operational requirements
    local services=(
        avahi-daemon      # mDNS/zeroconf — information disclosure
        cups              # printing daemon — unnecessary on servers
        isc-dhcp-server   # DHCP server (unless this is a DHCP server)
        bind9             # DNS server (unless this is a DNS server)
        vsftpd            # FTP server
        telnet            # cleartext remote access — never acceptable (NSA)
        rsh-server        # r-commands — never acceptable (NSA)
        rlogin            # r-commands — never acceptable (NSA)
        nis               # NIS — deprecated, insecure
        talk              # talk daemon
        ntalk             # ntalk daemon
        xinetd            # super-server (disable and use systemd sockets instead)
        rpcbind           # RPC portmapper (unless NFS is required)
        nfs-kernel-server # NFS (unless required)
    )

    for svc in "${services[@]}"; do
        if systemctl is-enabled "$svc" 2>/dev/null | grep -qE "enabled|static"; then
            systemctl disable --now "$svc" 2>/dev/null \
                && log_message "${BLUE}Disabled: $svc${NC}" \
                || log_message "${YELLOW}Could not disable: $svc (may not be installed)${NC}"
        fi
    done

    # NSA: disable core dumps system-wide
    backup_file /etc/security/limits.conf
    grep -q "hard core" /etc/security/limits.conf \
        || echo "* hard core 0" >> /etc/security/limits.conf

    # NSA: disable Ctrl+Alt+Del reboot (prevent physical console abuse)
    systemctl mask ctrl-alt-del.target 2>/dev/null || true

    log_message "${GREEN}Unnecessary services disabled${NC}"
}

# ============================================================================
# NEW: CORE DUMP RESTRICTION (NSA/STIG)
# ============================================================================

restrict_coredumps() {
    check_root
    log_message "${BLUE}=== Restricting Core Dumps (NSA/STIG) ===${NC}"

    # STIG: core dumps can expose sensitive data (passwords, keys, etc.)
    backup_file /etc/security/limits.conf
    grep -q "hard core" /etc/security/limits.conf \
        || echo "* hard core 0" >> /etc/security/limits.conf
    grep -q "soft core" /etc/security/limits.conf \
        || echo "* soft core 0" >> /etc/security/limits.conf

    # sysctl: disable core dumps for setuid processes
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/99-security.conf
    sysctl -w fs.suid_dumpable=0

    # systemd: disable core dumps via coredump.conf
    if [[ -d /etc/systemd ]]; then
        cat > /etc/systemd/coredump.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
    fi

    log_message "${GREEN}Core dump restrictions applied${NC}"
}

# ============================================================================
# RUN ALL
# ============================================================================

run_all_hardening() {
    log_message "${BLUE}=== Running All NSA/STIG Hardening Steps ===${NC}"
    log_message "${YELLOW}Backups stored in: $BACKUP_DIR${NC}"

    security_audit
    basic_hardening
    configure_firewall
    harden_ssh
    set_password_policy
    setup_fail2ban
    configure_updates
    fix_permissions
    configure_auditd        # NEW
    configure_mac           # NEW
    setup_aide              # NEW
    harden_grub             # NEW
    disable_unnecessary_services  # NEW
    restrict_coredumps      # NEW

    log_message "${GREEN}=== All NSA/STIG Hardening Completed ===${NC}"
    log_message "${YELLOW}Action items:${NC}"
    log_message "${YELLOW}  1. Review backup at: $BACKUP_DIR${NC}"
    log_message "${YELLOW}  2. Set SSH AllowUsers/AllowGroups in /etc/ssh/sshd_config.d/99-stig-hardening.conf${NC}"
    log_message "${YELLOW}  3. Enable Secure Boot in BIOS/UEFI (NSA guidance)${NC}"
    log_message "${YELLOW}  4. Set a GRUB password for physical security${NC}"
    log_message "${YELLOW}  5. Reboot to apply kernel parameters and GRUB changes${NC}"
    log_message "${YELLOW}  6. After reboot, run: aide --check${NC}"
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    if [[ $# -eq 0 ]]; then
        show_usage
        exit 0
    fi

    case "$1" in
        audit)              security_audit ;;
        harden)             basic_hardening ;;
        firewall)           configure_firewall ;;
        ssh-harden)         harden_ssh ;;
        password-policy)    set_password_policy ;;
        fail2ban)           setup_fail2ban ;;
        updates)            configure_updates ;;
        permissions)        fix_permissions ;;
        auditd)             configure_auditd ;;          # NEW
        mac)                configure_mac ;;             # NEW
        aide)               setup_aide ;;               # NEW
        grub-harden)        harden_grub ;;              # NEW
        disable-services)   disable_unnecessary_services ;; # NEW
        coredumps)          restrict_coredumps ;;       # NEW
        all)                run_all_hardening ;;
        *)
            echo -e "${RED}Unknown command: $1${NC}"
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
